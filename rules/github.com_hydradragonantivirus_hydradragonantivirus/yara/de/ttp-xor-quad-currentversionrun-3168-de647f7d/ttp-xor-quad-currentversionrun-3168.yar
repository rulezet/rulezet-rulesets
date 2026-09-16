rule TTP_XOR_QUAD_CurrentVersionRun_3168 {
  strings:
    $key_3168 = { 62 07 [2] 46 09 [2] 6d 25 [2] 43 07 [2] 57 1c [2] 58 06 [2] 46 1b [2] 44 1a [2] 5f 1c [2] 43 1b [2] 5f 34 }

  condition:
    any of them
}