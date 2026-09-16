rule TTP_XOR_QUAD_CurrentVersionRun_cc87 {
  strings:
    $key_cc87 = { 9f e8 [2] bb e6 [2] 90 ca [2] be e8 [2] aa f3 [2] a5 e9 [2] bb f4 [2] b9 f5 [2] a2 f3 [2] be f4 [2] a2 db }

  condition:
    any of them
}