rule TTP_XOR_QUAD_CurrentVersionRun_e815 {
  strings:
    $key_e815 = { bb 7a [2] 9f 74 [2] b4 58 [2] 9a 7a [2] 8e 61 [2] 81 7b [2] 9f 66 [2] 9d 67 [2] 86 61 [2] 9a 66 [2] 86 49 }

  condition:
    any of them
}