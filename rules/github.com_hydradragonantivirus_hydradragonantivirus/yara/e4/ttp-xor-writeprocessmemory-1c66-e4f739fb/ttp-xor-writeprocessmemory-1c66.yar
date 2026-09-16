rule TTP_XOR_WriteProcessMemory_1c66 {
  strings:
    $key_1c66 = { 4b 14 [2] 79 36 [2] 7f 03 [2] 51 03 [2] 6e 1f }

  condition:
    any of them
}