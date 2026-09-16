rule TTP_XOR_QUAD_CurrentVersionRun_e834 {
  strings:
    $key_e834 = { bb 5b [2] 9f 55 [2] b4 79 [2] 9a 5b [2] 8e 40 [2] 81 5a [2] 9f 47 [2] 9d 46 [2] 86 40 [2] 9a 47 [2] 86 68 }

  condition:
    any of them
}