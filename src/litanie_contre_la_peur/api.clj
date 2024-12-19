(ns litanie-contre-la-peur.api
  "Implementation of FFC MQV — C(1e, 2s) (MQV1) and C(2e, 2s) (MQV2) — as specified in NIST Special Publication 800-56A Revision 3.
  Includes key derivation via one-step method with SHA{224, 256, 384, 512}.
  Key confirmation is available for MQV1 in unilateral mode using HMAC-SHA{224, 256, 384, 512}."
  (:require [litanie-contre-la-peur.conversions :as conversions]
            [litanie-contre-la-peur.key-confirmation :as key-confirmation]
            [litanie-contre-la-peur.key-establishment :as key-establishment]
            [litanie-contre-la-peur.randomness :as randomness]))

(defn salt
  ([]
   (salt 12))
  ([n]
   (-> n
       randomness/random-bytes
       conversions/byte-array->hexadecimal-string)))

(def establish-shared-secret
  key-establishment/establish-key)

(def key-confirmation-function
  key-confirmation/mac-tag-function)
