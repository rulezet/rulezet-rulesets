rule TTP_XOR_WriteProcessMemory_7153 {
  strings:
    $key_7153 = { 26 21 [2] 14 03 [2] 12 36 [2] 3c 36 [2] 03 2a }

  condition:
    any of them
}