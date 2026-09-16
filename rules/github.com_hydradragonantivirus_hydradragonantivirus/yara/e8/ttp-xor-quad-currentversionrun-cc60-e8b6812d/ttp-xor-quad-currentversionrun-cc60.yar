rule TTP_XOR_QUAD_CurrentVersionRun_cc60 {
  strings:
    $key_cc60 = { 9f 0f [2] bb 01 [2] 90 2d [2] be 0f [2] aa 14 [2] a5 0e [2] bb 13 [2] b9 12 [2] a2 14 [2] be 13 [2] a2 3c }

  condition:
    any of them
}