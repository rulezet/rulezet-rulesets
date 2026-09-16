rule TTP_XOR_QUAD_CurrentVersionRun_e868 {
  strings:
    $key_e868 = { bb 07 [2] 9f 09 [2] b4 25 [2] 9a 07 [2] 8e 1c [2] 81 06 [2] 9f 1b [2] 9d 1a [2] 86 1c [2] 9a 1b [2] 86 34 }

  condition:
    any of them
}