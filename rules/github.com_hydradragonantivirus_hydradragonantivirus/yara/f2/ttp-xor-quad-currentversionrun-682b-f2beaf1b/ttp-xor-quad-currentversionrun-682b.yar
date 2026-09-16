rule TTP_XOR_QUAD_CurrentVersionRun_682b {
  strings:
    $key_682b = { 3b 44 [2] 1f 4a [2] 34 66 [2] 1a 44 [2] 0e 5f [2] 01 45 [2] 1f 58 [2] 1d 59 [2] 06 5f [2] 1a 58 [2] 06 77 }

  condition:
    any of them
}