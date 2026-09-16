rule TTP_XOR_QUAD_CurrentVersionRun_cc35 {
  strings:
    $key_cc35 = { 9f 5a [2] bb 54 [2] 90 78 [2] be 5a [2] aa 41 [2] a5 5b [2] bb 46 [2] b9 47 [2] a2 41 [2] be 46 [2] a2 69 }

  condition:
    any of them
}