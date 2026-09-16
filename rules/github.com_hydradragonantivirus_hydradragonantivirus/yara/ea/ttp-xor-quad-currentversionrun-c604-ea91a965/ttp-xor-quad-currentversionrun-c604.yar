rule TTP_XOR_QUAD_CurrentVersionRun_c604 {
  strings:
    $key_c604 = { 95 6b [2] b1 65 [2] 9a 49 [2] b4 6b [2] a0 70 [2] af 6a [2] b1 77 [2] b3 76 [2] a8 70 [2] b4 77 [2] a8 58 }

  condition:
    any of them
}