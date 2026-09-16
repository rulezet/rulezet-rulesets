rule TTP_XOR_WriteProcessMemory_7f46 {
  strings:
    $key_7f46 = { 28 34 [2] 1a 16 [2] 1c 23 [2] 32 23 [2] 0d 3f }

  condition:
    any of them
}