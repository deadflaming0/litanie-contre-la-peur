(ns litanie-contre-la-peur.core
  "Implementation of FFC MQV — C(2e, 2s) (MQV1) and C(1e, 2s) (MQV2) — as specified in NIST Special Publication 800-56A Revision 3."
  (:require [litanie-contre-la-peur.key-derivation :as key-derivation])
  (:import (java.math RoundingMode)))

(defn hex-str->big-int
  [x]
  (BigInteger. x 16))

(defn- z->Z
  [x p]
  (let [t (.bitLength p)
        n (/ t 8)
        ba (.toByteArray x)]
    (apply str (map #(format "%02x" %)
                    (take-last n ba)))))

(defn- shared-secret
  [{:keys [p q]} xA yB rA tA tB]
  (let [w (.toBigInteger
            (.divide (BigDecimal. (.subtract (BigInteger/valueOf (.bitLength q))
                                             BigInteger/ONE))
                     BigDecimal/TWO
                     RoundingMode/CEILING))
        two-pow-w (.pow BigInteger/TWO w)
        TA (.add (.mod tA two-pow-w) two-pow-w)
        SA (.mod (.add rA (.multiply TA xA)) q)
        TB (.add (.mod tB two-pow-w) two-pow-w)
        z (.modPow (.multiply tB (.modPow yB TB p)) SA p)]
    (if (or (<= z BigInteger/ONE)
            (= z (.subtract p BigInteger/ONE)))
      (throw (SecurityException. "Error during shared secret calculation."))
      (z->Z z p))))

(defn- valid-public-key?
  [{:keys [p q]} public-key]
  (and (< BigInteger/ONE public-key (.subtract p BigInteger/ONE))
       (= (.modPow public-key q p) BigInteger/ONE)
       (not (zero? (.mod public-key p)))))

(defn- valid-private-key?
  [{:keys [q]} private-key]
  (< BigInteger/ONE private-key (.subtract q BigInteger/ONE)))

(defn- valid-key-pair?
  [{:keys [p g] :as domain-parameters} private-key public-key]
  (and (valid-private-key? domain-parameters private-key)
       (valid-public-key? domain-parameters public-key)
       (= public-key (.modPow g private-key p))))

(defn- valid-domain-parameters?
  [{:keys [p q g]}]
  (and (zero? (.mod (.subtract p BigInteger/ONE) q))
       (= (.modPow g q p) BigInteger/ONE)))

(defn- valid-input?
  [scheme domain-parameters xA yA yB rA tA tB]
  (and (valid-domain-parameters? domain-parameters)
       (valid-key-pair? domain-parameters xA yA) ;; static key pair
       (valid-key-pair? domain-parameters rA tA) ;; ephemeral key pair
       (case scheme
         :mqv1 (valid-public-key? domain-parameters yB)
         :mqv2 (and (valid-public-key? domain-parameters yB)
                    (valid-public-key? domain-parameters tB)))))

(defn- scheme+mode->agreement-keys
  [scheme mode initiator-keys responder-keys]
  (case mode
    :init {:xA (:static-private-key initiator-keys)
           :yA (:static-public-key initiator-keys) ;; not used in `shared-secret`, used for validation purposes
           :yB (:static-public-key responder-keys)
           :rA (:ephemeral-private-key initiator-keys)
           :tA (:ephemeral-public-key initiator-keys)
           :tB (case scheme
                 :mqv1 (:static-public-key responder-keys)
                 :mqv2 (:ephemeral-public-key responder-keys))}
    :resp {:xA (:static-private-key responder-keys)
           :yA (:static-public-key responder-keys) ;; not used in `shared-secret`, used for validation purposes
           :yB (:static-public-key initiator-keys)
           :rA (:ephemeral-private-key responder-keys)
           :tA (:ephemeral-public-key responder-keys)
           :tB (case scheme
                 :mqv1 (:static-public-key initiator-keys)
                 :mqv2 (:ephemeral-public-key initiator-keys))}))

(defn agreement*
  [scheme mode domain-parameters initiator-keys responder-keys]
  (let [{:keys [xA yA yB rA tA tB]} (scheme+mode->agreement-keys
                                      scheme
                                      mode
                                      initiator-keys
                                      responder-keys)]
    (if (valid-input? scheme domain-parameters xA yA yB rA tA tB)
      (shared-secret domain-parameters xA yB rA tA tB)
      :bottom)))

(defn agreement
  [{:keys [scheme key-derivation #_key-confirmation]} ;; add :or
   mode
   dkm-randomness
   domain-parameters
   {initiator-identity :identity
    initiator-keys :keys}
   {responder-identity :identity
    responder-keys :keys}]
  (let [Z (agreement* scheme mode domain-parameters initiator-keys responder-keys)]
    (if (not= :bottom Z)
      (key-derivation/dkm
        (:algorithm key-derivation)
        Z
        {:L (:bit-length key-derivation)
         :other-info (concat initiator-identity
                             responder-identity
                             dkm-randomness)})
      Z)))

(comment
  (def protocol-settings
    {:scheme :mqv1 ;; | `:mqv2`
     :key-derivation {:algorithm :sha224 ;; | `:sha256` | `:sha384` | `:sha512`
                      :bit-length 112 ;; ???
                      }
     :key-confirmation {:type :none ;; | `:unilateral` | `:bilateral`
                        :algorithm :example1 ;; | `:example2` | `:example3`
                        }})
  )
