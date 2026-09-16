rule TTP_XOR_WriteProcessMemory_1dd5 {
  strings:
    $key_1dd5 = { 4a a7 [2] 78 85 [2] 7e b0 [2] 50 b0 [2] 6f ac }

  condition:
    any of them
}