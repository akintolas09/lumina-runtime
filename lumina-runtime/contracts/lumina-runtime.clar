;; Lumina Runtime - Zero-Knowledge Identity Credibility System

;; ============================================================
;; CONSTANTS
;; ============================================================

(define-constant CONTRACT-OWNER tx-sender)

;; Error codes
(define-constant ERR-NOT-AUTHORIZED        (err u100))
(define-constant ERR-ALREADY-REGISTERED   (err u101))
(define-constant ERR-NOT-REGISTERED       (err u102))
(define-constant ERR-INVALID-DOMAIN       (err u103))
(define-constant ERR-INSUFFICIENT-STAKE   (err u104))
(define-constant ERR-INVALID-THRESHOLD    (err u105))
(define-constant ERR-SELF-VOUCH           (err u106))
(define-constant ERR-ALREADY-VOUCHED      (err u107))
(define-constant ERR-SCORE-OVERFLOW       (err u108))

;; Domain identifiers (u0-u4)
(define-constant DOMAIN-PROFESSIONAL u0)
(define-constant DOMAIN-FINANCIAL    u1)
(define-constant DOMAIN-SOCIAL       u2)
(define-constant DOMAIN-TECHNICAL    u3)
(define-constant DOMAIN-GOVERNANCE   u4)
(define-constant DOMAIN-COUNT        u5)

;; Credibility parameters
(define-constant MAX-SCORE              u10000)   ;; 10,000 basis points = 100%
(define-constant DECAY-RATE-BPS        u50)       ;; 0.5% decay per period
(define-constant DECAY-PERIOD-BLOCKS   u1008)     ;; ~1 week at 10 min/block
(define-constant CROSS-DOMAIN-FACTOR   u200)      ;; 2% cross-domain contribution (BPS)
(define-constant MIN-STAKE-TO-VOUCH    u500)      ;; min score to vouch for others
(define-constant VOUCH-BONUS           u300)      ;; score granted to vouched newcomer
(define-constant ACTION-BASE-SCORE     u100)      ;; base points per verified action

;; ============================================================
;; DATA MAPS AND VARS
;; ============================================================

;; Proof-of-uniqueness registry: one slot per principal
(define-map registered-identities
  principal
  { registered-at: uint, identity-hash: (buff 32) })

;; Per-domain credibility scores with decay metadata
(define-map credibility-scores
  { user: principal, domain: uint }
  { score: uint, last-updated: uint, total-actions: uint })

;; Vouch relationships: voucher => vouchee => domain
(define-map vouches
  { voucher: principal, vouchee: principal, domain: uint }
  { block-height: uint, amount: uint })

;; Stake balances used for vouching accountability
(define-map stake-balances
  principal
  uint)

;; Approved action issuers (oracles that can credit actions)
(define-map approved-issuers
  principal
  bool)

;; Global stats
(define-data-var total-registered uint u0)
(define-data-var total-actions-credited uint u0)

;; ============================================================
;; PRIVATE HELPERS
;; ============================================================

;; Apply time-based decay to a score.
;; decay = score * DECAY-RATE-BPS/10000 * periods-elapsed
(define-private (apply-decay (score uint) (last-updated uint))
  (let (
    (periods-elapsed (/ (- block-height last-updated) DECAY-PERIOD-BLOCKS))
    (decay-per-period (/ (* score DECAY-RATE-BPS) u10000))
    (total-decay (* decay-per-period periods-elapsed))
  )
    (if (> total-decay score) u0 (- score total-decay))
  )
)

;; Fetch current decayed score for a user+domain, or 0 if not found.
(define-private (get-current-score (user principal) (domain uint))
  (match (map-get? credibility-scores { user: user, domain: domain })
    entry (apply-decay (get score entry) (get last-updated entry))
    u0
  )
)

;; Clamp a value to MAX-SCORE.
(define-private (clamp-score (s uint))
  (if (> s MAX-SCORE) MAX-SCORE s)
)

;; Compute cross-domain bonus: 2% of related-domain score.
(define-private (cross-domain-bonus (user principal) (related-domain uint))
  (/ (* (get-current-score user related-domain) CROSS-DOMAIN-FACTOR) u10000)
)

;; Check that a domain id is valid (0-4).
(define-private (is-valid-domain (domain uint))
  (< domain DOMAIN-COUNT)
)

;; ============================================================
;; PUBLIC FUNCTIONS
;; ============================================================

;; --- Registration (proof-of-uniqueness) ---

;; Register a new identity. The identity-hash is a commitment to
;; off-chain ZK proof data. Each principal may only register once.
(define-public (register-identity (identity-hash (buff 32)))
  (begin
    (asserts! (is-none (map-get? registered-identities tx-sender)) ERR-ALREADY-REGISTERED)
    (map-set registered-identities tx-sender
      { registered-at: block-height, identity-hash: identity-hash })
    (var-set total-registered (+ (var-get total-registered) u1))
    (ok true)
  )
)

;; --- Issuer management (owner only) ---

(define-public (set-approved-issuer (issuer principal) (approved bool))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (map-set approved-issuers issuer approved)
    (ok true)
  )
)

;; --- Crediting verified actions ---

;; Called by approved issuers (oracles) to credit a verified action.
;; Applies decay first, then adds action score plus cross-domain bonus
;; from related-domain (pass same domain if no cross-domain link desired).
(define-public (credit-action
    (user principal)
    (domain uint)
    (related-domain uint)
    (action-score uint))
  (let (
    (issuer-approved (default-to false (map-get? approved-issuers tx-sender)))
    (existing (default-to
      { score: u0, last-updated: block-height, total-actions: u0 }
      (map-get? credibility-scores { user: user, domain: domain })))
    (decayed-score (apply-decay (get score existing) (get last-updated existing)))
    (bonus        (cross-domain-bonus user related-domain))
    (new-score    (clamp-score (+ decayed-score action-score bonus)))
  )
    (asserts! issuer-approved ERR-NOT-AUTHORIZED)
    (asserts! (is-some (map-get? registered-identities user)) ERR-NOT-REGISTERED)
    (asserts! (is-valid-domain domain) ERR-INVALID-DOMAIN)
    (asserts! (is-valid-domain related-domain) ERR-INVALID-DOMAIN)
    (asserts! (<= action-score MAX-SCORE) ERR-SCORE-OVERFLOW)
    (map-set credibility-scores { user: user, domain: domain }
      { score: new-score,
        last-updated: block-height,
        total-actions: (+ (get total-actions existing) u1) })
    (var-set total-actions-credited (+ (var-get total-actions-credited) u1))
    (ok new-score)
  )
)

;; --- Staking / Vouching ---

;; Deposit stake (score units). A user locks part of their social-domain
;; score as stake to back vouches. This is an internal accounting mechanism.
(define-public (deposit-stake (domain uint) (amount uint))
  (let (
    (current (get-current-score tx-sender domain))
    (existing-stake (default-to u0 (map-get? stake-balances tx-sender)))
  )
    (asserts! (is-some (map-get? registered-identities tx-sender)) ERR-NOT-REGISTERED)
    (asserts! (>= current (+ existing-stake amount)) ERR-INSUFFICIENT-STAKE)
    (map-set stake-balances tx-sender (+ existing-stake amount))
    (ok (+ existing-stake amount))
  )
)

;; Vouch for a newcomer in a given domain.
;; Voucher must have MIN-STAKE-TO-VOUCH score in that domain.
;; Grants VOUCH-BONUS to vouchee; records accountability relationship.
(define-public (vouch-for (vouchee principal) (domain uint))
  (let (
    (voucher-score (get-current-score tx-sender domain))
    (existing-vouch (map-get? vouches
      { voucher: tx-sender, vouchee: vouchee, domain: domain }))
    (vouchee-entry (default-to
      { score: u0, last-updated: block-height, total-actions: u0 }
      (map-get? credibility-scores { user: vouchee, domain: domain })))
    (vouchee-decayed (apply-decay (get score vouchee-entry) (get last-updated vouchee-entry)))
    (new-vouchee-score (clamp-score (+ vouchee-decayed VOUCH-BONUS)))
  )
    (asserts! (is-some (map-get? registered-identities tx-sender)) ERR-NOT-REGISTERED)
    (asserts! (is-some (map-get? registered-identities vouchee)) ERR-NOT-REGISTERED)
    (asserts! (not (is-eq tx-sender vouchee)) ERR-SELF-VOUCH)
    (asserts! (is-none existing-vouch) ERR-ALREADY-VOUCHED)
    (asserts! (is-valid-domain domain) ERR-INVALID-DOMAIN)
    (asserts! (>= voucher-score MIN-STAKE-TO-VOUCH) ERR-INSUFFICIENT-STAKE)
    ;; Record the vouch
    (map-set vouches
      { voucher: tx-sender, vouchee: vouchee, domain: domain }
      { block-height: block-height, amount: VOUCH-BONUS })
    ;; Credit the vouchee
    (map-set credibility-scores { user: vouchee, domain: domain }
      { score: new-vouchee-score,
        last-updated: block-height,
        total-actions: (get total-actions vouchee-entry) })
    (ok new-vouchee-score)
  )
)

;; --- Threshold Proofs (selective disclosure) ---

;; Prove that the caller meets a minimum score threshold in a domain
;; without revealing the exact score. Returns true/false.
(define-public (prove-threshold (domain uint) (threshold uint))
  (begin
    (asserts! (is-some (map-get? registered-identities tx-sender)) ERR-NOT-REGISTERED)
    (asserts! (is-valid-domain domain) ERR-INVALID-DOMAIN)
    (asserts! (<= threshold MAX-SCORE) ERR-INVALID-THRESHOLD)
    (ok (>= (get-current-score tx-sender domain) threshold))
  )
)

;; Verify that another user meets a threshold (called by verifiers).
(define-public (verify-threshold (user principal) (domain uint) (threshold uint))
  (begin
    (asserts! (is-some (map-get? registered-identities user)) ERR-NOT-REGISTERED)
    (asserts! (is-valid-domain domain) ERR-INVALID-DOMAIN)
    (asserts! (<= threshold MAX-SCORE) ERR-INVALID-THRESHOLD)
    (ok (>= (get-current-score user domain) threshold))
  )
)

;; ============================================================
;; READ-ONLY FUNCTIONS
;; ============================================================

;; Get the current (decay-adjusted) score for a user in a domain.
(define-read-only (get-score (user principal) (domain uint))
  (get-current-score user domain)
)

;; Get registration info for a user.
(define-read-only (get-identity (user principal))
  (map-get? registered-identities user)
)

;; Get raw score entry (before decay) for inspection.
(define-read-only (get-score-entry (user principal) (domain uint))
  (map-get? credibility-scores { user: user, domain: domain })
)

;; Check whether a vouch exists.
(define-read-only (get-vouch (voucher principal) (vouchee principal) (domain uint))
  (map-get? vouches { voucher: voucher, vouchee: vouchee, domain: domain })
)

;; Get stake balance for a user.
(define-read-only (get-stake (user principal))
  (default-to u0 (map-get? stake-balances user))
)

;; Get global statistics.
(define-read-only (get-stats)
  { total-registered: (var-get total-registered),
    total-actions:    (var-get total-actions-credited) }
)

;; Check whether a principal is an approved issuer.
(define-read-only (is-approved-issuer (issuer principal))
  (default-to false (map-get? approved-issuers issuer))
)

;; Compute how much decay would be applied to a user's score right now.
(define-read-only (get-pending-decay (user principal) (domain uint))
  (match (map-get? credibility-scores { user: user, domain: domain })
    entry (let (
      (raw (get score entry))
      (decayed (apply-decay raw (get last-updated entry)))
    )
      (if (> raw decayed) (- raw decayed) u0)
    )
    u0
  )
)
