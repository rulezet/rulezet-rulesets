rule TTP_XOR_QUAD_CurrentVersionRun_e8f4 {
  strings:
    $key_e8f4 = { bb 9b [2] 9f 95 [2] b4 b9 [2] 9a 9b [2] 8e 80 [2] 81 9a [2] 9f 87 [2] 9d 86 [2] 86 80 [2] 9a 87 [2] 86 a8 }

  condition:
    any of them
}