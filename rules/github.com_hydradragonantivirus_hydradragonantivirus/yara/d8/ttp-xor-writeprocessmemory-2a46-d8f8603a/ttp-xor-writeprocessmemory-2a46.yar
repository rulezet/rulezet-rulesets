rule TTP_XOR_WriteProcessMemory_2a46 {
  strings:
    $key_2a46 = { 7d 34 [2] 4f 16 [2] 49 23 [2] 67 23 [2] 58 3f }

  condition:
    any of them
}