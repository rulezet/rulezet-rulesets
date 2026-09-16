rule TTP_XOR_QUAD_CurrentVersionRun_642b {
  strings:
    $key_642b = { 37 44 [2] 13 4a [2] 38 66 [2] 16 44 [2] 02 5f [2] 0d 45 [2] 13 58 [2] 11 59 [2] 0a 5f [2] 16 58 [2] 0a 77 }

  condition:
    any of them
}