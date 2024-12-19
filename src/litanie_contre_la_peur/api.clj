(ns litanie-contre-la-peur.api
  "Implementation of FFC MQV — C(1e, 2s) (MQV1) and C(2e, 2s) (MQV2) — as specified in NIST Special Publication 800-56A Revision 3.
  Includes key derivation via one-step method with SHA{224, 256, 384, 512}.
  Key confirmation is available for MQV1 in unilateral mode using HMAC-SHA{224, 256, 384, 512}."
  (:require [litanie-contre-la-peur.key-establishment :as key-establishment]
            [litanie-contre-la-peur.key-confirmation :as key-confirmation]))

;; 1. define protocol settings
(def protocol-settings
  {})

;; 2. define domain parameters

;; 3. generate initiator keys

;; 4. generate responder keys

;; 5. establish key

;; optional: confirm key
