rule TTP_XOR_QUAD_CurrentVersionRun_4065 {
  strings:
    $key_4065 = { 13 0a [2] 37 04 [2] 1c 28 [2] 32 0a [2] 26 11 [2] 29 0b [2] 37 16 [2] 35 17 [2] 2e 11 [2] 32 16 [2] 2e 39 }

  condition:
    any of them
}