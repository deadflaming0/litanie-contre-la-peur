(ns litanie-contre-la-peur.conversions)

(defn byte-array->hexadedecimal-string
  [x]
  (apply str (map #(format "%02x" %) x)))

(defn hexadedecimal-string->byte-array
  [x]
  (byte-array
   (map #(unchecked-byte (Integer/parseInt (apply str %) 16))
        (partition 2 x))))

(defn hexadecimal-string->big-integer
  [x]
  (BigInteger. x 16))

(defn big-integer->hexadecimal-string
  [x]
  (let [ba (.toByteArray x)]
    (byte-array->hexadedecimal-string ba)))
