rule TTP_XOR_QUAD_CurrentVersionRun_632b {
  strings:
    $key_632b = { 30 44 [2] 14 4a [2] 3f 66 [2] 11 44 [2] 05 5f [2] 0a 45 [2] 14 58 [2] 16 59 [2] 0d 5f [2] 11 58 [2] 0d 77 }

  condition:
    any of them
}