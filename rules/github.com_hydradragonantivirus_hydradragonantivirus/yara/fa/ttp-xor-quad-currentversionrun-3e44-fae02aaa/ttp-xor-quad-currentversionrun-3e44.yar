rule TTP_XOR_QUAD_CurrentVersionRun_3e44 {
  strings:
    $key_3e44 = { 6d 2b [2] 49 25 [2] 62 09 [2] 4c 2b [2] 58 30 [2] 57 2a [2] 49 37 [2] 4b 36 [2] 50 30 [2] 4c 37 [2] 50 18 }

  condition:
    any of them
}