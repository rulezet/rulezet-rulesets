rule TTP_XOR_QUAD_CurrentVersionRun_362b {
  strings:
    $key_362b = { 65 44 [2] 41 4a [2] 6a 66 [2] 44 44 [2] 50 5f [2] 5f 45 [2] 41 58 [2] 43 59 [2] 58 5f [2] 44 58 [2] 58 77 }

  condition:
    any of them
}