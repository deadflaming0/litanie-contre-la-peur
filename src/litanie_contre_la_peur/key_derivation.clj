(ns litanie-contre-la-peur.key-derivation
  (:require [litanie-contre-la-peur.conversions :as conversions])
  (:import (java.security MessageDigest)))

(defn fixed-info
  [role initiator-identity responder-identity salt]
  (case role
    :initiator (concat initiator-identity
                       responder-identity
                       salt)
    :responder (concat responder-identity
                       initiator-identity
                       salt)))

(defn dkm
  [algorithm Z {:keys [L fixed-info]}]
  (let [Z-bytes (conversions/hexadedecimal-string->byte-array Z)
        fixed-info-bytes (conversions/hexadedecimal-string->byte-array fixed-info)
        input (byte-array (concat [0 0 0 1] Z-bytes fixed-info-bytes))
        H (MessageDigest/getInstance (name algorithm))
        dkm-bytes (.digest H input)]
    (conversions/byte-array->hexadedecimal-string (take (quot L 8) ;; add `L` validation
                                                        dkm-bytes))))
