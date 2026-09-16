rule TTP_XOR_WriteProcessMemory_2a86 {
  strings:
    $key_2a86 = { 7d f4 [2] 4f d6 [2] 49 e3 [2] 67 e3 [2] 58 ff }

  condition:
    any of them
}