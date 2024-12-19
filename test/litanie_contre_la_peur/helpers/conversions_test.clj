(ns litanie-contre-la-peur.helpers.conversions-test
  {:clj-kondo/config '{:linters {:refer-all {:level :off}}}}
  (:require [clojure.string :as string]
            [clojure.test :refer :all]
            [litanie-contre-la-peur.helpers.conversions :as conversions]))

(deftest byte-array->hexadecimal-string-test
  (testing "happy path"
    (are [input expected] (= expected
                             (conversions/byte-array->hexadecimal-string input))
      (byte-array [0x00 0x01 0x02]) "000102"
      (byte-array [0xff]) "ff"
      (byte-array [0x10 0x20 0x30]) "102030"
      (byte-array [0x0f]) "0f"
      (byte-array [0xaa 0xbb 0xcc]) "aabbcc"))
  (testing "sad path"
    (is (string/blank? (conversions/byte-array->hexadecimal-string nil)))
    (is (string/blank? (conversions/byte-array->hexadecimal-string [])))
    (is (thrown? Exception (conversions/byte-array->hexadecimal-string "not a byte array")))))

(deftest hexadecimal-string->byte-array-test
  (testing "happy path"
    (are [input expected] (java.util.Arrays/equals
                           expected
                           (conversions/hexadecimal-string->byte-array input))
      "000102" (byte-array [0x00 0x01 0x02])
      "ff" (byte-array [0x0ff])
      "102030" (byte-array [0x10 0x20 0x30])
      "0f" (byte-array [0x0f])
      "aabbcc" (byte-array [0xaa 0xbb 0xcc])))
  (testing "sad path"
    (is (empty? (conversions/hexadecimal-string->byte-array nil)))
    (is (empty? (conversions/hexadecimal-string->byte-array [])))
    (is (thrown? NumberFormatException (conversions/hexadecimal-string->byte-array "not a hex str")))))

(deftest hexadecimal-string->big-integer-test
  (are [input expected] (= expected (conversions/hexadecimal-string->big-integer input))
    "00" (BigInteger. "0")
    "ff" (BigInteger. "ff" 16)
    "102030" (BigInteger. "102030" 16)))

(deftest big-integer->hexadecimal-string-test
  (are [input expected] (= expected (conversions/big-integer->hexadecimal-string input))
    (BigInteger. "0") "00"
    (BigInteger. "ff" 16) "00ff"
    (BigInteger. "102030" 16) "102030"))
