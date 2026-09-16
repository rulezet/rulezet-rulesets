rule TTP_XOR_QUAD_CurrentVersionRun_cc4d {
  strings:
    $key_cc4d = { 9f 22 [2] bb 2c [2] 90 00 [2] be 22 [2] aa 39 [2] a5 23 [2] bb 3e [2] b9 3f [2] a2 39 [2] be 3e [2] a2 11 }

  condition:
    any of them
}