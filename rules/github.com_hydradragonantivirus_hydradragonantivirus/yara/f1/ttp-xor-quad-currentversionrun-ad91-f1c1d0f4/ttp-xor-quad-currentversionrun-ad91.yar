rule TTP_XOR_QUAD_CurrentVersionRun_ad91 {
  strings:
    $key_ad91 = { fe fe [2] da f0 [2] f1 dc [2] df fe [2] cb e5 [2] c4 ff [2] da e2 [2] d8 e3 [2] c3 e5 [2] df e2 [2] c3 cd }

  condition:
    any of them
}