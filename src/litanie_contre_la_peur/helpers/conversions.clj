(ns litanie-contre-la-peur.helpers.conversions)

(defn byte-array->hexadecimal-string
  [x]
  (apply str (map #(format "%02x" %) x)))

(defn hexadecimal-string->byte-array
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
    (byte-array->hexadecimal-string ba)))
