(ns litanie-contre-la-peur.key-confirmation
  (:require [litanie-contre-la-peur.conversions :as conversions])
  (:import (javax.crypto Mac)
           (javax.crypto.spec SecretKeySpec)))

(defn- eq?
  "Taken from https://github.com/weavejester/crypto-equality/blob/master/src/crypto/equality.clj."
  [a b]
  (let [a (map int a), b (map int b)]
    (if (and a b (= (count a) (count b)))
      (zero? (reduce bit-or 0 (map bit-xor a b)))
      false)))

(defn- compute-mac-tag
  [algorithm mac-key mac-data]
  (let [algorithm-name (name algorithm)
        mac-key' (SecretKeySpec. (conversions/hex-str->byte-array mac-key) algorithm-name)
        mac-data' (conversions/hex-str->byte-array mac-data)
        mac (Mac/getInstance algorithm-name)]
    (.init mac mac-key')
    (conversions/byte-array->hex-str (.doFinal mac mac-data'))))

(defn- make-mac-data
  [message-string & segments]
  (apply concat message-string segments))

(def ^:private kc-1-u
  (-> "KC_1_U" .getBytes conversions/byte-array->hex-str))
(def ^:private kc-1-v
  (-> "KC_1_V" .getBytes conversions/byte-array->hex-str))

(defn- extract-mac-key
  [dkm]
  (let [mid (quot (count dkm) 2)]
    (subs dkm 0 mid)))

(defn- unsupported-operation?
  [scheme {key-confirmation-algorithm :algorithm
           key-confirmation-type :type}]
  (let [supported-algorithms #{:hmacsha224 :hmacsha256 :hmacsha384 :hmacsha512}]
    (or (not= scheme :mqv1)
        (not (contains? supported-algorithms key-confirmation-algorithm))
        (not= key-confirmation-type :unilateral))))

(defn mac-tag-function
  [{:keys [scheme key-confirmation]}
   key-agreement-role
   key-confirmation-role
   dkm]
  (if (unsupported-operation? scheme key-confirmation)
    (throw (UnsupportedOperationException. "Not implemented yet."))
    (let [mac-key (extract-mac-key dkm)
          expression [scheme
                      (:type key-confirmation)
                      key-agreement-role
                      key-confirmation-role]]
      (case expression
        [:mqv1 :unilateral :initiator :provider]

        ;; MacData = "KC_1_U" ||
        ;;           (:static-public-key initiator) (IUTid) ||
        ;;           (:static-public-key responder) (CAVSid) ||
        ;;           (:ephemeral-public-key initiator) (YephemIUT)
        ;;           nonce (responder) (NonceEphemCAVS)

        (fn [static-public-key-1 static-public-key-2 ephemeral-public-key-1 nonce]
          (compute-mac-tag (:algorithm key-confirmation)
                           mac-key
                           (make-mac-data kc-1-u
                                          (conversions/big-int->hex-str static-public-key-1)
                                          (conversions/big-int->hex-str static-public-key-2)
                                          (conversions/big-int->hex-str ephemeral-public-key-1)
                                          nonce)))

        [:mqv1 :unilateral :responder :recipient]

        ;; MacData = "KC_1_U" ||
        ;;           (:static-public-key responder) (CAVSid) ||
        ;;           (:static-public-key initiator) (IUTid) ||
        ;;           (:ephemeral-public-key responder) (YephemCAVS) ||
        ;;           nonce (initiator) (NonceEphemIUT)

        (fn [static-public-key-1 static-public-key-2 ephemeral-public-key-1 nonce candidate-mac-tag]
          (eq? candidate-mac-tag
               (compute-mac-tag (:algorithm key-confirmation)
                                mac-key
                                (make-mac-data kc-1-u
                                               (conversions/big-int->hex-str static-public-key-1)
                                               (conversions/big-int->hex-str static-public-key-2)
                                               (conversions/big-int->hex-str ephemeral-public-key-1)
                                               nonce))))

        [:mqv1 :unilateral :responder :provider]

        ;; MacData = "KC_1_V" ||
        ;;           (:static-public-key initiator) (IUTid) ||
        ;;           (:static-public-key responder) (CAVSid) ||
        ;;           (:ephemeral-public-key responder) (YephemCAVS)

        (fn [static-public-key-1 static-public-key-2 ephemeral-public-key-1]
          (compute-mac-tag (:algorithm key-confirmation)
                           mac-key
                           (make-mac-data kc-1-v
                                          (conversions/big-int->hex-str static-public-key-1)
                                          (conversions/big-int->hex-str static-public-key-2)
                                          (conversions/big-int->hex-str ephemeral-public-key-1))))

        [:mqv1 :unilateral :initiator :recipient]

        ;; MacData = "KC_1_V" ||
        ;;           (:static-public-key responder) (CAVSid) ||
        ;;           (:static-public-key initiator) (IUTid) ||
        ;;           (:ephemeral-public-key initiator) (YephemIUT)

        (fn [static-public-key-1 static-public-key-2 ephemeral-public-key-1 candidate-mac-tag]
          (eq? candidate-mac-tag
               (compute-mac-tag (:algorithm key-confirmation)
                                mac-key
                                (make-mac-data kc-1-v
                                               (conversions/big-int->hex-str static-public-key-1)
                                               (conversions/big-int->hex-str static-public-key-2)
                                               (conversions/big-int->hex-str ephemeral-public-key-1)))))))))
