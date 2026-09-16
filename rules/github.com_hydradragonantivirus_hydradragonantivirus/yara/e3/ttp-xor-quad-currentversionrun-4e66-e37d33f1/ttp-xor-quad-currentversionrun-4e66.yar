rule TTP_XOR_QUAD_CurrentVersionRun_4e66 {
  strings:
    $key_4e66 = { 1d 09 [2] 39 07 [2] 12 2b [2] 3c 09 [2] 28 12 [2] 27 08 [2] 39 15 [2] 3b 14 [2] 20 12 [2] 3c 15 [2] 20 3a }

  condition:
    any of them
}