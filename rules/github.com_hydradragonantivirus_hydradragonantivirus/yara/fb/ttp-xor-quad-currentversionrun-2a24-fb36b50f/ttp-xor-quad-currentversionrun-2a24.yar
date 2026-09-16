rule TTP_XOR_QUAD_CurrentVersionRun_2a24 {
  strings:
    $key_2a24 = { 79 4b [2] 5d 45 [2] 76 69 [2] 58 4b [2] 4c 50 [2] 43 4a [2] 5d 57 [2] 5f 56 [2] 44 50 [2] 58 57 [2] 44 78 }

  condition:
    any of them
}