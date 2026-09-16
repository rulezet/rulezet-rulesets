rule TTP_XOR_QUAD_CurrentVersionRun_e837 {
  strings:
    $key_e837 = { bb 58 [2] 9f 56 [2] b4 7a [2] 9a 58 [2] 8e 43 [2] 81 59 [2] 9f 44 [2] 9d 45 [2] 86 43 [2] 9a 44 [2] 86 6b }

  condition:
    any of them
}