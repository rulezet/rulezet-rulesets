rule TTP_XOR_QUAD_CurrentVersionRun_7b65 {
  strings:
    $key_7b65 = { 28 0a [2] 0c 04 [2] 27 28 [2] 09 0a [2] 1d 11 [2] 12 0b [2] 0c 16 [2] 0e 17 [2] 15 11 [2] 09 16 [2] 15 39 }

  condition:
    any of them
}