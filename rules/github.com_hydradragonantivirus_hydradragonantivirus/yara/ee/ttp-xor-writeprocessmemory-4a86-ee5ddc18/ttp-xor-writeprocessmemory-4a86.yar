rule TTP_XOR_WriteProcessMemory_4a86 {
  strings:
    $key_4a86 = { 1d f4 [2] 2f d6 [2] 29 e3 [2] 07 e3 [2] 38 ff }

  condition:
    any of them
}