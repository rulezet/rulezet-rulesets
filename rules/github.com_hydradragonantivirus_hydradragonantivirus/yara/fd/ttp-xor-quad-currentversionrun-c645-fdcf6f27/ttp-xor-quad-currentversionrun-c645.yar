rule TTP_XOR_QUAD_CurrentVersionRun_c645 {
  strings:
    $key_c645 = { 95 2a [2] b1 24 [2] 9a 08 [2] b4 2a [2] a0 31 [2] af 2b [2] b1 36 [2] b3 37 [2] a8 31 [2] b4 36 [2] a8 19 }

  condition:
    any of them
}