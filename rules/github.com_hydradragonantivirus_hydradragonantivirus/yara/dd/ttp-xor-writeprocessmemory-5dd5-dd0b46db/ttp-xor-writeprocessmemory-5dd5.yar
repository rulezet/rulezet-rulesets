rule TTP_XOR_WriteProcessMemory_5dd5 {
  strings:
    $key_5dd5 = { 0a a7 [2] 38 85 [2] 3e b0 [2] 10 b0 [2] 2f ac }

  condition:
    any of them
}