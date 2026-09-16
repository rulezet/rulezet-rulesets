rule TTP_XOR_QUAD_CurrentVersionRun_6d65 {
  strings:
    $key_6d65 = { 3e 0a [2] 1a 04 [2] 31 28 [2] 1f 0a [2] 0b 11 [2] 04 0b [2] 1a 16 [2] 18 17 [2] 03 11 [2] 1f 16 [2] 03 39 }

  condition:
    any of them
}