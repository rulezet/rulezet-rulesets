rule TTP_XOR_QUAD_CurrentVersionRun_e804 {
  strings:
    $key_e804 = { bb 6b [2] 9f 65 [2] b4 49 [2] 9a 6b [2] 8e 70 [2] 81 6a [2] 9f 77 [2] 9d 76 [2] 86 70 [2] 9a 77 [2] 86 58 }

  condition:
    any of them
}