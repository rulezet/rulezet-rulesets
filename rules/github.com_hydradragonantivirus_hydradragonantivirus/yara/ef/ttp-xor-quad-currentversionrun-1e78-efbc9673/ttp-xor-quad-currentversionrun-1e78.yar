rule TTP_XOR_QUAD_CurrentVersionRun_1e78 {
  strings:
    $key_1e78 = { 4d 17 [2] 69 19 [2] 42 35 [2] 6c 17 [2] 78 0c [2] 77 16 [2] 69 0b [2] 6b 0a [2] 70 0c [2] 6c 0b [2] 70 24 }

  condition:
    any of them
}