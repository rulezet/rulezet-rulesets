rule TTP_XOR_QUAD_CurrentVersionRun_cc85 {
  strings:
    $key_cc85 = { 9f ea [2] bb e4 [2] 90 c8 [2] be ea [2] aa f1 [2] a5 eb [2] bb f6 [2] b9 f7 [2] a2 f1 [2] be f6 [2] a2 d9 }

  condition:
    any of them
}