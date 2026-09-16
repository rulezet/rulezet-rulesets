rule TTP_XOR_QUAD_CurrentVersionRun_7e65 {
  strings:
    $key_7e65 = { 2d 0a [2] 09 04 [2] 22 28 [2] 0c 0a [2] 18 11 [2] 17 0b [2] 09 16 [2] 0b 17 [2] 10 11 [2] 0c 16 [2] 10 39 }

  condition:
    any of them
}