rule TTP_XOR_QUAD_CurrentVersionRun_c727 {
  strings:
    $key_c727 = { 94 48 [2] b0 46 [2] 9b 6a [2] b5 48 [2] a1 53 [2] ae 49 [2] b0 54 [2] b2 55 [2] a9 53 [2] b5 54 [2] a9 7b }

  condition:
    any of them
}