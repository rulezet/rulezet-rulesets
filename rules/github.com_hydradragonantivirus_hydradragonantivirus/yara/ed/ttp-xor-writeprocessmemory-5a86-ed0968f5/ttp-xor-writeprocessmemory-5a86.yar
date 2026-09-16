rule TTP_XOR_WriteProcessMemory_5a86 {
  strings:
    $key_5a86 = { 0d f4 [2] 3f d6 [2] 39 e3 [2] 17 e3 [2] 28 ff }

  condition:
    any of them
}