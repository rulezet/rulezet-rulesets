rule TTP_XOR_QUAD_CurrentVersionRun_3339 {
  strings:
    $key_3339 = { 60 56 [2] 44 58 [2] 6f 74 [2] 41 56 [2] 55 4d [2] 5a 57 [2] 44 4a [2] 46 4b [2] 5d 4d [2] 41 4a [2] 5d 65 }

  condition:
    any of them
}