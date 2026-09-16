rule TTP_XOR_QUAD_CurrentVersionRun_ad97 {
  strings:
    $key_ad97 = { fe f8 [2] da f6 [2] f1 da [2] df f8 [2] cb e3 [2] c4 f9 [2] da e4 [2] d8 e5 [2] c3 e3 [2] df e4 [2] c3 cb }

  condition:
    any of them
}