rule TTP_XOR_QUAD_CurrentVersionRun_c627 {
  strings:
    $key_c627 = { 95 48 [2] b1 46 [2] 9a 6a [2] b4 48 [2] a0 53 [2] af 49 [2] b1 54 [2] b3 55 [2] a8 53 [2] b4 54 [2] a8 7b }

  condition:
    any of them
}