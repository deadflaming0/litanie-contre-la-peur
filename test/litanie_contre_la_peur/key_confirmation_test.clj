(ns litanie-contre-la-peur.key-confirmation-test
  (:require [clojure.test :refer :all]
            [litanie-contre-la-peur.conversions :as conversions]
            [litanie-contre-la-peur.key-confirmation :as key-confirmation]))

(def initiator
  {:static-private-key (conversions/hex-str->big-int "6f378694fd0affa3d67bd1324adf5d0b2b55d11f8912751dc538d7d6")
   :static-public-key (conversions/hex-str->big-int "289035379caf0d7cc8984102654202dd027c6a74f7f0fcd634faeef2c0917210b997d507625ca535947f02d78c3cf7266791f3e95cf73f9aca3be7b18c05a66fc33d746e02811eb16a44b3e6af012cdccdc2f84d3a0a9984fa2d034eeba596b634a4c9e5ab29d8787d31711b09ea77c991391cad3a0c574af807e31a1d7395745b29b9847419213d519a4210cb5c3f0601c6505380e102f13d2e6d473daf611a0aa2cbb47d85529434f17d1014b876c918ee2c866acd1b3c59a8de76a41675dc3f1967c748c077ed0be035365c7a7148c6295eb83fa53eec4bea9569d0775e451c8d1171bc532b7714214d9f22bacbce3efbf57e6c9283b8140f20fecea867ab")
   :ephemeral-private-key (conversions/hex-str->big-int "12da574432595fc792a11084046348248e98f571162821efacf45276")
   :ephemeral-public-key (conversions/hex-str->big-int "6588df436aab3233e49503aee9f76eb87ab393af96c0f77038f22821aec1c979d2652db07397d199252e0be4309c62516f02e2c09c61429c9bc1fc1d2d74cb3d15a10febd78ffc4eac8d98b49b6f71eccac85f60340c395f9ad74e29d7d276db407bc7a3cff2bb585841163c2afc6207eccef4706c5f7f8c786341c89466e57b64c5f9056efde08cef7ba95e826f59e0260c6536e348c8e0045099761cd38a1079382ddc5db88ac376a788838b15d4dcac35e668f67b2159ef82128276ba9d01c3bd12def396c16eb0832e2892b8d7017ae2f57f35248fa06a29be48a96f5c01611d59c63fb54b30a4a2c786c6aefd16292f16eceaaf796aec923aa22115e303")})

(def responder
  {:static-private-key (conversions/hex-str->big-int "6d55fe00150639518d741a9495a959d0e3abfe206776567f11c6cca2")
   :static-public-key (conversions/hex-str->big-int "10431e92b1efe26a389e559066e635c2a6b564d39bfd5902d3b3ad003d5321fb8ea361983a4389e9e6121714eed2b33fbf95dd45d49324d0420ba58e6b2c9809235760c254b44cf59a217e98a77f6065bccee3100dd7049f39fd4faaf5af8ea4c4ab6c2453c5e37a962bcb8f33941ca75cc4ef1d3ab73558db448d023ca1369d5d993583b582ad285491705930f81a2e8ab9cc4c82aee16f49807a5d13b3e0e953ea0ad7b51998428cfe3559f208f42d41346d3c1cf2c5b342f9f55c19cef3a19939d716e6e61e4bec92670e60a404985b5553d02fec43ef7dd3064ee857f422ccbcb7edf2ba72e18591c6bc1cf5922c43fdd642379af6a78ad1b05b655b2a0f")})

(deftest key-confirmation
  (testing "mqv1, hmac-sha224, unilateral, initiator -> responder"
    (let [protocol-settings {:scheme :mqv1
                             :key-confirmation {:algorithm :hmacsha224
                                                :type :unilateral}}
          dkm "fadefeedcafefadef00dbabefadedead"
          nonce "a1b2c3d4e5"
          sign-fn (key-confirmation/mac-tag-function protocol-settings
                                                     :initiator
                                                     :provider
                                                     dkm)
          computed-mac-tag (sign-fn (:static-public-key initiator)
                                    (:static-public-key responder)
                                    (:ephemeral-public-key initiator)
                                    nonce)
          verify-fn (key-confirmation/mac-tag-function protocol-settings
                                                       :responder
                                                       :recipient
                                                       dkm)
          mac-tag-result (verify-fn (:static-public-key initiator)
                                    (:static-public-key responder)
                                    (:ephemeral-public-key initiator)
                                    nonce
                                    computed-mac-tag)]
      (is (= (* 4 (count computed-mac-tag)) 224))
      (is (true? mac-tag-result))))
  (testing "mqv1, hmac-sha256, unilateral, initiator -> responder"
    (let [protocol-settings {:scheme :mqv1
                             :key-confirmation {:algorithm :hmacsha256
                                                :type :unilateral}}
          dkm "fadefeedcafefadef00dbabefadedead"
          nonce "a1b2c3d4e5"
          sign-fn (key-confirmation/mac-tag-function protocol-settings
                                                     :initiator
                                                     :provider
                                                     dkm)
          computed-mac-tag (sign-fn (:static-public-key initiator)
                                    (:static-public-key responder)
                                    (:ephemeral-public-key initiator)
                                    nonce)
          verify-fn (key-confirmation/mac-tag-function protocol-settings
                                                       :responder
                                                       :recipient
                                                       dkm)
          mac-tag-result (verify-fn (:static-public-key initiator)
                                    (:static-public-key responder)
                                    (:ephemeral-public-key initiator)
                                    nonce
                                    computed-mac-tag)]
      (is (= (* 4 (count computed-mac-tag)) 256))
      (is (true? mac-tag-result))))
  (testing "mqv1, hmac-sha384, unilateral, initiator -> responder"
    (let [protocol-settings {:scheme :mqv1
                             :key-confirmation {:algorithm :hmacsha384
                                                :type :unilateral}}
          dkm "fadefeedcafefadef00dbabefadedead"
          nonce "a1b2c3d4e5"
          sign-fn (key-confirmation/mac-tag-function protocol-settings
                                                     :initiator
                                                     :provider
                                                     dkm)
          computed-mac-tag (sign-fn (:static-public-key initiator)
                                    (:static-public-key responder)
                                    (:ephemeral-public-key initiator)
                                    nonce)
          verify-fn (key-confirmation/mac-tag-function protocol-settings
                                                       :responder
                                                       :recipient
                                                       dkm)
          mac-tag-result (verify-fn (:static-public-key initiator)
                                    (:static-public-key responder)
                                    (:ephemeral-public-key initiator)
                                    nonce
                                    computed-mac-tag)]
      (is (= (* 4 (count computed-mac-tag)) 384))
      (is (true? mac-tag-result))))
  (testing "mqv1, hmac-sha512, unilateral, initiator -> responder"
    (let [protocol-settings {:scheme :mqv1
                             :key-confirmation {:algorithm :hmacsha512
                                                :type :unilateral}}
          dkm "fadefeedcafefadef00dbabefadedead"
          nonce "a1b2c3d4e5"
          sign-fn (key-confirmation/mac-tag-function protocol-settings
                                                     :initiator
                                                     :provider
                                                     dkm)
          computed-mac-tag (sign-fn (:static-public-key initiator)
                                    (:static-public-key responder)
                                    (:ephemeral-public-key initiator)
                                    nonce)
          verify-fn (key-confirmation/mac-tag-function protocol-settings
                                                       :responder
                                                       :recipient
                                                       dkm)
          mac-tag-result (verify-fn (:static-public-key initiator)
                                    (:static-public-key responder)
                                    (:ephemeral-public-key initiator)
                                    nonce
                                    computed-mac-tag)]
      (is (= (* 4 (count computed-mac-tag)) 512))
      (is (true? mac-tag-result)))))
