rule TTP_XOR_QUAD_CurrentVersionRun_cc72 {
  strings:
    $key_cc72 = { 9f 1d [2] bb 13 [2] 90 3f [2] be 1d [2] aa 06 [2] a5 1c [2] bb 01 [2] b9 00 [2] a2 06 [2] be 01 [2] a2 2e }

  condition:
    any of them
}