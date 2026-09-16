rule TTP_XOR_QUAD_CurrentVersionRun_3144 {
  strings:
    $key_3144 = { 62 2b [2] 46 25 [2] 6d 09 [2] 43 2b [2] 57 30 [2] 58 2a [2] 46 37 [2] 44 36 [2] 5f 30 [2] 43 37 [2] 5f 18 }

  condition:
    any of them
}