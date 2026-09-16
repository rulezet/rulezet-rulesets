rule TTP_XOR_QUAD_CurrentVersionRun_3e35 {
  strings:
    $key_3e35 = { 6d 5a [2] 49 54 [2] 62 78 [2] 4c 5a [2] 58 41 [2] 57 5b [2] 49 46 [2] 4b 47 [2] 50 41 [2] 4c 46 [2] 50 69 }

  condition:
    any of them
}