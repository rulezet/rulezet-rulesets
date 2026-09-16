rule TTP_XOR_WriteProcessMemory_1146 {
  strings:
    $key_1146 = { 46 34 [2] 74 16 [2] 72 23 [2] 5c 23 [2] 63 3f }

  condition:
    any of them
}