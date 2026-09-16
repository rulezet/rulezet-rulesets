rule TTP_XOR_QUAD_CurrentVersionRun_1e68 {
  strings:
    $key_1e68 = { 4d 07 [2] 69 09 [2] 42 25 [2] 6c 07 [2] 78 1c [2] 77 06 [2] 69 1b [2] 6b 1a [2] 70 1c [2] 6c 1b [2] 70 34 }

  condition:
    any of them
}