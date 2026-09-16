rule TTP_XOR_WriteProcessMemory_3de0 {
  strings:
    $key_3de0 = { 6a 92 [2] 58 b0 [2] 5e 85 [2] 70 85 [2] 4f 99 }

  condition:
    any of them
}