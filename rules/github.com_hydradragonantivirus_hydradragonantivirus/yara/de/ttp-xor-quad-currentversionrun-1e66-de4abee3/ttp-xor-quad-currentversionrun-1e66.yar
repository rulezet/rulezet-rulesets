rule TTP_XOR_QUAD_CurrentVersionRun_1e66 {
  strings:
    $key_1e66 = { 4d 09 [2] 69 07 [2] 42 2b [2] 6c 09 [2] 78 12 [2] 77 08 [2] 69 15 [2] 6b 14 [2] 70 12 [2] 6c 15 [2] 70 3a }

  condition:
    any of them
}