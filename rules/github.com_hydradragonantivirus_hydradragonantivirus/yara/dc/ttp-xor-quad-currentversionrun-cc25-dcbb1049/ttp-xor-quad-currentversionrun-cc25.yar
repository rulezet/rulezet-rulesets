rule TTP_XOR_QUAD_CurrentVersionRun_cc25 {
  strings:
    $key_cc25 = { 9f 4a [2] bb 44 [2] 90 68 [2] be 4a [2] aa 51 [2] a5 4b [2] bb 56 [2] b9 57 [2] a2 51 [2] be 56 [2] a2 79 }

  condition:
    any of them
}