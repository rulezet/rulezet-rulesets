rule TTP_XOR_QUAD_CurrentVersionRun_1165 {
  strings:
    $key_1165 = { 42 0a [2] 66 04 [2] 4d 28 [2] 63 0a [2] 77 11 [2] 78 0b [2] 66 16 [2] 64 17 [2] 7f 11 [2] 63 16 [2] 7f 39 }

  condition:
    any of them
}