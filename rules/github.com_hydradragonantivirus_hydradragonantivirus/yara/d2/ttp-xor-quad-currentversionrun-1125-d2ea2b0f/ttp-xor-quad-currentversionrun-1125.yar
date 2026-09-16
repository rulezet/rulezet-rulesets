rule TTP_XOR_QUAD_CurrentVersionRun_1125 {
  strings:
    $key_1125 = { 42 4a [2] 66 44 [2] 4d 68 [2] 63 4a [2] 77 51 [2] 78 4b [2] 66 56 [2] 64 57 [2] 7f 51 [2] 63 56 [2] 7f 79 }

  condition:
    any of them
}