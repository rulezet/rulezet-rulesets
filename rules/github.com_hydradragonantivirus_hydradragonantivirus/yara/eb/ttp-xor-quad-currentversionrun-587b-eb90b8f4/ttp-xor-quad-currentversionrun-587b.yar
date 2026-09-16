rule TTP_XOR_QUAD_CurrentVersionRun_587b {
  strings:
    $key_587b = { 0b 14 [2] 2f 1a [2] 04 36 [2] 2a 14 [2] 3e 0f [2] 31 15 [2] 2f 08 [2] 2d 09 [2] 36 0f [2] 2a 08 [2] 36 27 }

  condition:
    any of them
}