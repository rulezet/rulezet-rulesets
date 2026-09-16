rule TTP_XOR_QUAD_CurrentVersionRun_c1f4 {
  strings:
    $key_c1f4 = { 92 9b [2] b6 95 [2] 9d b9 [2] b3 9b [2] a7 80 [2] a8 9a [2] b6 87 [2] b4 86 [2] af 80 [2] b3 87 [2] af a8 }

  condition:
    any of them
}