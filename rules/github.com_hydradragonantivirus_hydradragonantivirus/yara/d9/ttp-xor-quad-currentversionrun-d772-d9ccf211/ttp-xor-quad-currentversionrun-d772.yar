rule TTP_XOR_QUAD_CurrentVersionRun_d772 {
  strings:
    $key_d772 = { 84 1d [2] a0 13 [2] 8b 3f [2] a5 1d [2] b1 06 [2] be 1c [2] a0 01 [2] a2 00 [2] b9 06 [2] a5 01 [2] b9 2e }

  condition:
    any of them
}