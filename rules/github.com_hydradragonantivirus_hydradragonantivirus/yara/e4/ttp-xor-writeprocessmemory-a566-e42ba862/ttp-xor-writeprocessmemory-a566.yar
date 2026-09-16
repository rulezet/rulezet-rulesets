rule TTP_XOR_WriteProcessMemory_a566 {
  strings:
    $key_a566 = { f2 14 [2] c0 36 [2] c6 03 [2] e8 03 [2] d7 1f }

  condition:
    any of them
}