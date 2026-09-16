rule TTP_XOR_QUAD_CurrentVersionRun_cc0b {
  strings:
    $key_cc0b = { 9f 64 [2] bb 6a [2] 90 46 [2] be 64 [2] aa 7f [2] a5 65 [2] bb 78 [2] b9 79 [2] a2 7f [2] be 78 [2] a2 57 }

  condition:
    any of them
}