rule TTP_XOR_QUAD_CurrentVersionRun_6065 {
  strings:
    $key_6065 = { 33 0a [2] 17 04 [2] 3c 28 [2] 12 0a [2] 06 11 [2] 09 0b [2] 17 16 [2] 15 17 [2] 0e 11 [2] 12 16 [2] 0e 39 }

  condition:
    any of them
}