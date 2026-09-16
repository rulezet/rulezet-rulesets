rule TTP_XOR_WriteProcessMemory_7256 {
  strings:
    $key_7256 = { 25 24 [2] 17 06 [2] 11 33 [2] 3f 33 [2] 00 2f }

  condition:
    any of them
}