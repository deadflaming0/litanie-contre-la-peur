(ns litanie-contre-la-peur.randomness
  (:import (java.security SecureRandom)))

(defn random-bytes ;; TODO: ver tamanho mínimo p/ salt
  [n]
  (let [secure-random (SecureRandom.)
        ba (byte-array n)]
    (.nextBytes secure-random ba)))
