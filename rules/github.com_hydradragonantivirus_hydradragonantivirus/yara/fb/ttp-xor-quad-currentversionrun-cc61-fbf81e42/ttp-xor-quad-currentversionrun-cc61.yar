rule TTP_XOR_QUAD_CurrentVersionRun_cc61 {
  strings:
    $key_cc61 = { 9f 0e [2] bb 00 [2] 90 2c [2] be 0e [2] aa 15 [2] a5 0f [2] bb 12 [2] b9 13 [2] a2 15 [2] be 12 [2] a2 3d }

  condition:
    any of them
}