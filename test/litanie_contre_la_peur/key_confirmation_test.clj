(ns litanie-contre-la-peur.key-confirmation-test
  (:require [clojure.test :refer :all]
            [litanie-contre-la-peur.conversions :as conversions]
            [litanie-contre-la-peur.key-confirmation :as kc]))

(def initiator
  {:static-private-key (conversions/hex-str->big-int "6f378694fd0affa3d67bd1324adf5d0b2b55d11f8912751dc538d7d6")
   :static-public-key (conversions/hex-str->big-int "289035379caf0d7cc8984102654202dd027c6a74f7f0fcd634faeef2c0917210b997d507625ca535947f02d78c3cf7266791f3e95cf73f9aca3be7b18c05a66fc33d746e02811eb16a44b3e6af012cdccdc2f84d3a0a9984fa2d034eeba596b634a4c9e5ab29d8787d31711b09ea77c991391cad3a0c574af807e31a1d7395745b29b9847419213d519a4210cb5c3f0601c6505380e102f13d2e6d473daf611a0aa2cbb47d85529434f17d1014b876c918ee2c866acd1b3c59a8de76a41675dc3f1967c748c077ed0be035365c7a7148c6295eb83fa53eec4bea9569d0775e451c8d1171bc532b7714214d9f22bacbce3efbf57e6c9283b8140f20fecea867ab")
   :ephemeral-private-key (conversions/hex-str->big-int "12da574432595fc792a11084046348248e98f571162821efacf45276")
   :ephemeral-public-key (conversions/hex-str->big-int "6588df436aab3233e49503aee9f76eb87ab393af96c0f77038f22821aec1c979d2652db07397d199252e0be4309c62516f02e2c09c61429c9bc1fc1d2d74cb3d15a10febd78ffc4eac8d98b49b6f71eccac85f60340c395f9ad74e29d7d276db407bc7a3cff2bb585841163c2afc6207eccef4706c5f7f8c786341c89466e57b64c5f9056efde08cef7ba95e826f59e0260c6536e348c8e0045099761cd38a1079382ddc5db88ac376a788838b15d4dcac35e668f67b2159ef82128276ba9d01c3bd12def396c16eb0832e2892b8d7017ae2f57f35248fa06a29be48a96f5c01611d59c63fb54b30a4a2c786c6aefd16292f16eceaaf796aec923aa22115e303")})

(def responder
  {:static-private-key (conversions/hex-str->big-int "6d55fe00150639518d741a9495a959d0e3abfe206776567f11c6cca2")
   :static-public-key (conversions/hex-str->big-int "10431e92b1efe26a389e559066e635c2a6b564d39bfd5902d3b3ad003d5321fb8ea361983a4389e9e6121714eed2b33fbf95dd45d49324d0420ba58e6b2c9809235760c254b44cf59a217e98a77f6065bccee3100dd7049f39fd4faaf5af8ea4c4ab6c2453c5e37a962bcb8f33941ca75cc4ef1d3ab73558db448d023ca1369d5d993583b582ad285491705930f81a2e8ab9cc4c82aee16f49807a5d13b3e0e953ea0ad7b51998428cfe3559f208f42d41346d3c1cf2c5b342f9f55c19cef3a19939d716e6e61e4bec92670e60a404985b5553d02fec43ef7dd3064ee857f422ccbcb7edf2ba72e18591c6bc1cf5922c43fdd642379af6a78ad1b05b655b2a0f")
   :ephemeral-private-key (conversions/hex-str->big-int "70c17bfee2271831a74719b0a652669f40c038fb8bc357d3ffde543c")
   :ephemeral-public-key (conversions/hex-str->big-int "d76f7d64e433036c7ae3f6cbafda73e7b3fdb93aa0806083ffb0f73b6b6d0e0bebbba199a685a99ee045cfb637c64225124485fdfd45bacee06bc2d507ebdbeaa7e91cccad843995c571801e08b5dbde7d6110420f4fb723776b2c6b26d7471dea5e1137142f60c7ed6cba6e8396dbff65ac0d3c5b17000fb18e56dea4af8ac11f11929ff3fa7877064a816e47bb7202366d1a3a8a0f0761670d191ff23ba900aac9522d7a3bb91385493f91f991b1211051476c6f83fe19c15e45081c772a98c19bd50905df089faa25e1798e7b711d7f88d173889ffc557c1b42d8379a4d649953e7c46ec629789d8c409d8b7b810159ff4395f1862a204763b000fe8b3f28")})

(def dkm "fadefeedcafefadef00dbabefadedead")

(def nonce "a1b2c3d4e5")

(def supported-algorithms [:hmacsha224
                           :hmacsha256
                           :hmacsha384
                           :hmacsha512])

(defn- run-key-confirmation-test
  [algorithm role direction dkm expected-mac-tag-length nonce?]
  (let [protocol-settings {:scheme :mqv1
                           :key-confirmation {:algorithm algorithm
                                              :type :unilateral}}
        sign-fn (kc/mac-tag-function protocol-settings role :provider dkm)
        computed-mac-tag (if nonce?
                           (sign-fn (:static-public-key initiator)
                                    (:static-public-key responder)
                                    (:ephemeral-public-key initiator)
                                    nonce)
                           (sign-fn (:static-public-key initiator)
                                    (:static-public-key responder)
                                    (:ephemeral-public-key initiator)))
        verify-fn (kc/mac-tag-function protocol-settings direction :recipient dkm)
        mac-tag-result (if nonce?
                         (verify-fn (:static-public-key initiator)
                                    (:static-public-key responder)
                                    (:ephemeral-public-key initiator)
                                    nonce
                                    computed-mac-tag)
                         (verify-fn (:static-public-key initiator)
                                    (:static-public-key responder)
                                    (:ephemeral-public-key initiator)
                                    computed-mac-tag))]
    (is (= (* 4 (count computed-mac-tag)) expected-mac-tag-length))
    (is (true? mac-tag-result))))

(deftest key-confirmation
  (testing "happy path: mac tag verification succeeds"
    (doseq [algorithm supported-algorithms]
      (let [mac-tag-length (case algorithm
                             :hmacsha224 224
                             :hmacsha256 256
                             :hmacsha384 384
                             :hmacsha512 512)]
        (testing (str "algorithm: " (name algorithm) ", initiator to responder")
          (run-key-confirmation-test algorithm :initiator :responder dkm mac-tag-length true))
        (testing (str "algorithm: " (name algorithm) ", responder to initiator")
          (run-key-confirmation-test algorithm :responder :initiator dkm mac-tag-length false)))))
  (testing "sad path"
    (testing "not implemented operations throw an exception"
      (is (thrown? UnsupportedOperationException
                   (kc/mac-tag-function
                    {:scheme :mqv2
                     :key-confirmation {:algorithm :hmacsha224
                                        :type :unilateral}}
                    :initiator
                    :provider
                    "")))
      (is (thrown? UnsupportedOperationException
                   (kc/mac-tag-function
                    {:scheme :mqv1
                     :key-confirmation {:algorithm :hmacsha1
                                        :type :unilateral}}
                    :initiator
                    :provider
                    "")))
      (is (thrown? UnsupportedOperationException
                   (kc/mac-tag-function
                    {:scheme :mqv1
                     :key-confirmation {:algorithm :hmacsha224
                                        :type :bilateral}}
                    :initiator
                    :provider
                    "")))
      (testing "inexistent roles also throw an exception"
        (is (thrown-with-msg? IllegalArgumentException #"No matching clause:"
                              (kc/mac-tag-function
                               {:scheme :mqv1
                                :key-confirmation {:algorithm :hmacsha224
                                                   :type :unilateral}}
                               :something
                               :provider
                               "")))
        (is (thrown-with-msg? IllegalArgumentException #"No matching clause:"
                              (kc/mac-tag-function
                               {:scheme :mqv1
                                :key-confirmation {:algorithm :hmacsha224
                                                   :type :unilateral}}
                               :initiator
                               :something
                               "")))))
    (testing "mac tag mismatch between provider and recipient"
      (let [protocol-settings {:scheme :mqv1
                               :key-confirmation {:algorithm :hmacsha224
                                                  :type :unilateral}}
            sign-fn (kc/mac-tag-function protocol-settings
                                         :initiator
                                         :provider
                                         dkm)
            computed-mac-tag (sign-fn (:static-public-key initiator)
                                      (:static-public-key responder)
                                      (:ephemeral-public-key initiator)
                                      nonce)]
        (testing "correct but swapped arguments"
          (let [verify-fn (kc/mac-tag-function protocol-settings
                                               :responder
                                               :recipient
                                               dkm)
                mac-tag-result (verify-fn (:static-public-key responder) ;; swapped
                                          (:static-public-key initiator) ;; swapped
                                          (:ephemeral-public-key initiator)
                                          nonce
                                          computed-mac-tag)]
            (is (false? mac-tag-result))))
        (testing "different static public key"
          (let [verify-fn (kc/mac-tag-function protocol-settings
                                               :responder
                                               :recipient
                                               dkm)
                mac-tag-result (verify-fn (conversions/hex-str->big-int "470aa7ed8a2d969b66e645db7d1b04859f2ba8681c5a36dd45968b2721c39ead34d0a8990b76a0f85dd637d644e15483923dc23be47f5fecee00367442faf047b35a9657334b8143fcc5a4974903af3ea464d1df4228c81d6190c4a608503d5a7ffc2dddaca876db5be4de862ff35966f2e5b98d7de1dcacc81dfa745a0b147d9ac9caa4df587ffab6e66f23c8704d2cfc0bcfef424a3eefe3c2656133d733e34667a14ae9ffcd343599864a57eb64c7c67f8d26beb4f7c3d7281c9a1b7cf2fdaa01734781a4466b4b7ad8eff0a5e69f6a046968f5796f64b40f4ca3a843f78cf911244d810cffe2424802ea809aec0366e54075d8ed716a07cd558e81cb84fa")
                                          (:static-public-key responder)
                                          (:ephemeral-public-key initiator)
                                          nonce
                                          computed-mac-tag)]
            (is (false? mac-tag-result))))
        (testing "different dkm"
          (let [verify-fn (kc/mac-tag-function protocol-settings
                                               :responder
                                               :recipient
                                               "3974bbe69f839827")
                mac-tag-result (verify-fn (:static-public-key initiator)
                                          (:static-public-key responder)
                                          (:ephemeral-public-key initiator)
                                          nonce
                                          computed-mac-tag)]
            (is (false? mac-tag-result))))
        (testing "different nonce"
          (let [verify-fn (kc/mac-tag-function protocol-settings
                                               :responder
                                               :recipient
                                               dkm)
                mac-tag-result (verify-fn (:static-public-key initiator)
                                          (:static-public-key responder)
                                          (:ephemeral-public-key initiator)
                                          "e5d4c3b2a1"
                                          computed-mac-tag)]
            (is (false? mac-tag-result))))
        (testing "different mac tag"
          (let [verify-fn (kc/mac-tag-function protocol-settings
                                               :responder
                                               :recipient
                                               dkm)
                another-mac-tag "0930559505bc481811c8c411ff5d063b3318f69e36171905857750d1"
                mac-tag-result (verify-fn (:static-public-key initiator)
                                          (:static-public-key responder)
                                          (:ephemeral-public-key initiator)
                                          nonce
                                          another-mac-tag)]
            (is (false? mac-tag-result))
              ;; explicit check
            (is (not= computed-mac-tag another-mac-tag))))))))
