rule TTP_XOR_WriteProcessMemory_6f46 {
  strings:
    $key_6f46 = { 38 34 [2] 0a 16 [2] 0c 23 [2] 22 23 [2] 1d 3f }

  condition:
    any of them
}