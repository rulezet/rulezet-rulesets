rule TTP_XOR_QUAD_CurrentVersionRun_2a2b {
  strings:
    $key_2a2b = { 79 44 [2] 5d 4a [2] 76 66 [2] 58 44 [2] 4c 5f [2] 43 45 [2] 5d 58 [2] 5f 59 [2] 44 5f [2] 58 58 [2] 44 77 }

  condition:
    any of them
}