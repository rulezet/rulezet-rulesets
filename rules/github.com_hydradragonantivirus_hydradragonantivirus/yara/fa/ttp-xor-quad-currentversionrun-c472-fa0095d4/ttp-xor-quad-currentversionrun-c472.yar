rule TTP_XOR_QUAD_CurrentVersionRun_c472 {
  strings:
    $key_c472 = { 97 1d [2] b3 13 [2] 98 3f [2] b6 1d [2] a2 06 [2] ad 1c [2] b3 01 [2] b1 00 [2] aa 06 [2] b6 01 [2] aa 2e }

  condition:
    any of them
}