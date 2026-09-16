rule TTP_XOR_QUAD_CurrentVersionRun_cc47 {
  strings:
    $key_cc47 = { 9f 28 [2] bb 26 [2] 90 0a [2] be 28 [2] aa 33 [2] a5 29 [2] bb 34 [2] b9 35 [2] a2 33 [2] be 34 [2] a2 1b }

  condition:
    any of them
}