(ns litanie-contre-la-peur.building-blocks.key-establishment
  (:require [litanie-contre-la-peur.building-blocks.key-derivation :as key-derivation]
            [litanie-contre-la-peur.helpers.conversions :as conversions])
  (:import (java.math RoundingMode)))

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
      :bottom
      (let [t (.bitLength p)
            n (quot t 4)
            Z (conversions/big-integer->hexadecimal-string z)]
        (subs Z (- (count Z) n))))))

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

(defn- scheme+role->agreement-keys
  [scheme role initiator responder]
  (case role
    :initiator
    {:xA (:static-private-key initiator)
     :yA (:static-public-key initiator) ;; not used in `shared-secret`, used for validation purposes
     :yB (:static-public-key responder)
     :rA (:ephemeral-private-key initiator)
     :tA (:ephemeral-public-key initiator)
     :tB (case scheme
           :mqv1 (:static-public-key responder)
           :mqv2 (:ephemeral-public-key responder))}

    :responder
    {:xA (:static-private-key responder)
     :yA (:static-public-key responder) ;; not used in `shared-secret`, used for validation purposes
     :yB (:static-public-key initiator)
     :rA (:ephemeral-private-key responder)
     :tA (:ephemeral-public-key responder)
     :tB (case scheme
           :mqv1 (:static-public-key initiator)
           :mqv2 (:ephemeral-public-key initiator))}))

(defn agreement ;; TODO: make it private
  [scheme role domain-parameters initiator responder]
  (let [{:keys [xA yA yB rA tA tB]} (scheme+role->agreement-keys
                                     scheme
                                     role
                                     initiator
                                     responder)]
    (if (valid-input? scheme domain-parameters xA yA yB rA tA tB)
      (shared-secret domain-parameters xA yB rA tA tB)
      :bottom)))

(defn establish-key
  [{:keys [scheme key-derivation]}
   role
   domain-parameters
   initiator
   responder]
  (let [result (agreement scheme role domain-parameters initiator responder)]
    (if (not= :bottom result)
      (let [L (:bit-length key-derivation)
            fixed-info (key-derivation/fixed-info role
                                                  (-> initiator
                                                      :static-public-key
                                                      conversions/big-integer->hexadecimal-string)
                                                  (-> responder
                                                      :static-public-key
                                                      conversions/big-integer->hexadecimal-string)
                                                  (:salt key-derivation))]
        (key-derivation/dkm (:algorithm key-derivation)
                            result
                            {:L L
                             :fixed-info fixed-info}))
      result)))
