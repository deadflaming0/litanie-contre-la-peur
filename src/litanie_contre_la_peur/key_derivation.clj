(ns litanie-contre-la-peur.key-derivation
  (:import (java.security MessageDigest)))

(defn- hex-str->byte-array
  [x]
  (byte-array
   (map #(unchecked-byte (Integer/parseInt (apply str %) 16))
        (partition 2 x))))

(defn- byte-array->hex-str
  [x]
  (apply str (map #(format "%02x" %) x)))

(defn dkm
  [algorithm Z {:keys [L other-info]}]
  (let [Z-bytes (hex-str->byte-array Z)
        other-info-bytes (hex-str->byte-array other-info)
        input (byte-array (concat [0 0 0 1] Z-bytes other-info-bytes))
        H (MessageDigest/getInstance (name algorithm))
        dkm-bytes (.digest H input)]
    (byte-array->hex-str (take (quot L 8) dkm-bytes))))
