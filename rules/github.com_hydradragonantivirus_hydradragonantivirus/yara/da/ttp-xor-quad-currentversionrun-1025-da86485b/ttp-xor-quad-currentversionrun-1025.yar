rule TTP_XOR_QUAD_CurrentVersionRun_1025 {
  strings:
    $key_1025 = { 43 4a [2] 67 44 [2] 4c 68 [2] 62 4a [2] 76 51 [2] 79 4b [2] 67 56 [2] 65 57 [2] 7e 51 [2] 62 56 [2] 7e 79 }

  condition:
    any of them
}