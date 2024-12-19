# litanie-contre-la-peur

This project implements a partial Clojure FFC (Finite Field Cryptography) version of the [Menezes-Qu-Vanstone (MQV)](https://en.wikipedia.org/wiki/MQV) authenticated key agreement protocol ([original paper](https://cacr.uwaterloo.ca/techreports/1998/corr98-05.pdf)), specifically MQV1 (C(1e, 2s)) and MQV2 (C(2e, 2s)), as defined in [NIST SP 800-56A Revision 3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf). The shared secret is derived using a one-step key derivation method according to [NIST SP 800-56C Revision 2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf) (Option 1 with SHA2). Optionally, parties may confirm the derived secret keying material through [key confirmation](https://csrc.nist.gov/glossary/term/key_confirmation) in unilateral mode (in MQV1) using HMAC-SHA2.

## Running the protocol, step by step

```clj
(require '[litanie-contre-la-peur.api :as api])
(require '[litanie-contre-la-peur.conversions :as conversions])
(require '[litanie-contre-la-peur.randomness :as randomness])

;; 1. define protocol settings (alternatives are presented in decreasing order of security preference)
(def protocol-settings
  {:scheme :mqv2 ;; | :mqv1
   :key-derivation {:algorithm :sha512 ;; | :sha384 | :sha256 | :sha224
                    :bit-length 512
                    :salt (conversions/byte-array->hexadecimal-string
                            (randomness/random-bytes 12))}
   ;; optional (highly recommended!), but only available when using :mqv1 scheme as of now
   :key-confirmation {:algorithm :hmacsha512 ;; :hmacsha384 | :hmacsha256 | :hmacsha224
                      :type :unilateral}})

;; 2. define domain parameters: `p`, `q` and `g`
(def domain-parameters
  {:p (conversions/hexadecimal-string->big-integer "define-p-here")
   :q (conversions/hexadecimal-string->big-integer "define-q-here")
   :g (conversions/hexadecimal-string->big-integer "define-g-here")})

;; 3. generate initiator keys
(def initiator-keys
  {:static-private-key (conversions/hexadecimal-string->big-integer "static-private-key-goes-here")
   :static-public-key (conversions/hexadecimal-string->big-integer "static-public-key-goes-here")
   :ephemeral-private-key (conversions/hexadecimal-string->big-integer "ephemeral-private-key-goes-here")
   :ephemeral-public-key (conversions/hexadecimal-string->big-integer "ephemeral-public-key-goes-here")})

;; 4. generate responder keys
(def responder-keys
  {:static-private-key (conversions/hexadecimal-string->big-integer "static-private-key-goes-here")
   :static-public-key (conversions/hexadecimal-string->big-integer "static-public-key-goes-here")
   :ephemeral-private-key (conversions/hexadecimal-string->big-integer "ephemeral-private-key-goes-here")
   :ephemeral-public-key (conversions/hexadecimal-string->big-integer "ephemeral-public-key-goes-here")})

;; 5. establish key

;; initiator runs:
(def secret-keying-material
  (api/establish-key
    protocol-settings
    :initiator
    initiator-keys
    responder-keys ;; only public keys
  ))

;; and responder runs the same, but with keys swapped:
(def secret-keying-material
  (api/establish-key
    protocol-settings
    :responder
    responder-keys
    initiator-keys ;; only public keys
  ))

;; 6. confirm key (again: this is optional)

;; 6.1. responder (recipient) sends a nonce through a network call:
(def nonce
  (conversions/byte-array->hexadecimal-string
    (randomness/random-bytes 12)))

;; 6.2. then initiator (provider) runs:
(def sign-fn (api/mac-tag-function
               protocol-settings
               :initiator
               :provider ;; that is, the one that generates the mac tag
               secret-keying-material))
(def mac-tag (sign-fn (:static-public-key initiator)
                      (:static-public-key responder)
                      (:ephemeral-public-key initiator)
                      nonce))

;; 6.3. finally, initiator sends `mac-tag` over the wire, then responder runs:
(def verify-fn (api/mac-tag-function
                 protocol-settings
                 :responder
                 :recipient ;; that is, the one that verifies the signature matches
                 secret-keying-material))
(def verify-result (verify-fn (:static-public-key initiator)
                              (:static-public-key responder)
                              (:ephemeral-public-key initiator)
                              nonce
                              mac-tag)
(assert (true? verify-result))
```
