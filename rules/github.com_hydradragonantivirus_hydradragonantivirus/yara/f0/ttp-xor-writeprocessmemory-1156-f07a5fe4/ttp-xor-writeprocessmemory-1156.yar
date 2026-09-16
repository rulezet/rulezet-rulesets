rule TTP_XOR_WriteProcessMemory_1156 {
  strings:
    $key_1156 = { 46 24 [2] 74 06 [2] 72 33 [2] 5c 33 [2] 63 2f }

  condition:
    any of them
}