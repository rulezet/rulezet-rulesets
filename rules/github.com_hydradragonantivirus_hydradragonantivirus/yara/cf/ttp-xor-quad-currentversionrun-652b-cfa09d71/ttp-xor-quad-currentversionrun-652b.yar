rule TTP_XOR_QUAD_CurrentVersionRun_652b {
  strings:
    $key_652b = { 36 44 [2] 12 4a [2] 39 66 [2] 17 44 [2] 03 5f [2] 0c 45 [2] 12 58 [2] 10 59 [2] 0b 5f [2] 17 58 [2] 0b 77 }

  condition:
    any of them
}