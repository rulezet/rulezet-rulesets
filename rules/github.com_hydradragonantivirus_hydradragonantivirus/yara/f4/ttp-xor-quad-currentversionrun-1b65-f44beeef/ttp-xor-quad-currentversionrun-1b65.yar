rule TTP_XOR_QUAD_CurrentVersionRun_1b65 {
  strings:
    $key_1b65 = { 48 0a [2] 6c 04 [2] 47 28 [2] 69 0a [2] 7d 11 [2] 72 0b [2] 6c 16 [2] 6e 17 [2] 75 11 [2] 69 16 [2] 75 39 }

  condition:
    any of them
}