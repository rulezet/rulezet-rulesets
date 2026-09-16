rule TTP_XOR_QUAD_CurrentVersionRun_0025 {
  strings:
    $key_0025 = { 53 4a [2] 77 44 [2] 5c 68 [2] 72 4a [2] 66 51 [2] 69 4b [2] 77 56 [2] 75 57 [2] 6e 51 [2] 72 56 [2] 6e 79 }

  condition:
    any of them
}