(ns litanie-contre-la-peur.conversions)

(defn byte-array->hex-str
  [x]
  (apply str (map #(format "%02x" %) x)))

(defn hex-str->byte-array
  [x]
  (byte-array
   (map #(unchecked-byte (Integer/parseInt (apply str %) 16))
        (partition 2 x))))

(defn hex-str->big-int
  [x]
  (BigInteger. x 16))

(defn big-int->hex-str
  [x]
  (let [ba (.toByteArray x)]
    (byte-array->hex-str ba)))
