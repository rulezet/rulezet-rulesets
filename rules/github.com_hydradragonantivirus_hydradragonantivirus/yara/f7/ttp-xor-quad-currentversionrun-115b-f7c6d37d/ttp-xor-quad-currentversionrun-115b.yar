rule TTP_XOR_QUAD_CurrentVersionRun_115b {
  strings:
    $key_115b = { 42 34 [2] 66 3a [2] 4d 16 [2] 63 34 [2] 77 2f [2] 78 35 [2] 66 28 [2] 64 29 [2] 7f 2f [2] 63 28 [2] 7f 07 }

  condition:
    any of them
}