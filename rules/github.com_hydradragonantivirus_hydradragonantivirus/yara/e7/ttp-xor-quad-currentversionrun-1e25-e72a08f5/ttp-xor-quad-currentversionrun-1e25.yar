rule TTP_XOR_QUAD_CurrentVersionRun_1e25 {
  strings:
    $key_1e25 = { 4d 4a [2] 69 44 [2] 42 68 [2] 6c 4a [2] 78 51 [2] 77 4b [2] 69 56 [2] 6b 57 [2] 70 51 [2] 6c 56 [2] 70 79 }

  condition:
    any of them
}