rule TTP_XOR_WriteProcessMemory_2a82 {
  strings:
    $key_2a82 = { 7d f0 [2] 4f d2 [2] 49 e7 [2] 67 e7 [2] 58 fb }

  condition:
    any of them
}