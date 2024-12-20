(ns litanie-contre-la-peur.helpers.randomness
  (:import (java.security SecureRandom)))

(defn random-bytes ;; TODO: add `n` validation
  [n]
  (let [secure-random (SecureRandom.)
        ba (byte-array n)]
    (.nextBytes secure-random ba)))
