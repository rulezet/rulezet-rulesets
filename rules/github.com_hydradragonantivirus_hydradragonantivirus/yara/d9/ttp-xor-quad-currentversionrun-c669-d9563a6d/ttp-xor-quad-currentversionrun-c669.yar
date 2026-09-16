rule TTP_XOR_QUAD_CurrentVersionRun_c669 {
  strings:
    $key_c669 = { 95 06 [2] b1 08 [2] 9a 24 [2] b4 06 [2] a0 1d [2] af 07 [2] b1 1a [2] b3 1b [2] a8 1d [2] b4 1a [2] a8 35 }

  condition:
    any of them
}