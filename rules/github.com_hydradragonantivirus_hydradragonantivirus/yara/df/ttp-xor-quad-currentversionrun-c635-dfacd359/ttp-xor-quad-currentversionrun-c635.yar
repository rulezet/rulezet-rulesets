rule TTP_XOR_QUAD_CurrentVersionRun_c635 {
  strings:
    $key_c635 = { 95 5a [2] b1 54 [2] 9a 78 [2] b4 5a [2] a0 41 [2] af 5b [2] b1 46 [2] b3 47 [2] a8 41 [2] b4 46 [2] a8 69 }

  condition:
    any of them
}