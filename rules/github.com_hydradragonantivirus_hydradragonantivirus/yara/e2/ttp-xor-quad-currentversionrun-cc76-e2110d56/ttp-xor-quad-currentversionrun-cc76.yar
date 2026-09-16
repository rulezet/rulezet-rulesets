rule TTP_XOR_QUAD_CurrentVersionRun_cc76 {
  strings:
    $key_cc76 = { 9f 19 [2] bb 17 [2] 90 3b [2] be 19 [2] aa 02 [2] a5 18 [2] bb 05 [2] b9 04 [2] a2 02 [2] be 05 [2] a2 2a }

  condition:
    any of them
}