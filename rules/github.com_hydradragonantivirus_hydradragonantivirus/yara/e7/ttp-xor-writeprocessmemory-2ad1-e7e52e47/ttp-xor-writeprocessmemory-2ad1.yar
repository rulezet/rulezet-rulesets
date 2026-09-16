rule TTP_XOR_WriteProcessMemory_2ad1 {
  strings:
    $key_2ad1 = { 7d a3 [2] 4f 81 [2] 49 b4 [2] 67 b4 [2] 58 a8 }

  condition:
    any of them
}