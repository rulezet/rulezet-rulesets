rule TTP_XOR_WriteProcessMemory_0f86 {
  strings:
    $key_0f86 = { 58 f4 [2] 6a d6 [2] 6c e3 [2] 42 e3 [2] 7d ff }

  condition:
    any of them
}