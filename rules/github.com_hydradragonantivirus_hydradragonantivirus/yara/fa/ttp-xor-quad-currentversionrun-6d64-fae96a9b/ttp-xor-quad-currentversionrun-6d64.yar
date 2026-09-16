rule TTP_XOR_QUAD_CurrentVersionRun_6d64 {
  strings:
    $key_6d64 = { 3e 0b [2] 1a 05 [2] 31 29 [2] 1f 0b [2] 0b 10 [2] 04 0a [2] 1a 17 [2] 18 16 [2] 03 10 [2] 1f 17 [2] 03 38 }

  condition:
    any of them
}