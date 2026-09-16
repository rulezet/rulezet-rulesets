rule TTP_XOR_QUAD_CurrentVersionRun_cc83 {
  strings:
    $key_cc83 = { 9f ec [2] bb e2 [2] 90 ce [2] be ec [2] aa f7 [2] a5 ed [2] bb f0 [2] b9 f1 [2] a2 f7 [2] be f0 [2] a2 df }

  condition:
    any of them
}