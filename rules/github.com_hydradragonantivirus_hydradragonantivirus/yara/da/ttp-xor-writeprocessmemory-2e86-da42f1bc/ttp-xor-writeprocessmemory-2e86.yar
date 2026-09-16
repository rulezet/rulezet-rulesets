rule TTP_XOR_WriteProcessMemory_2e86 {
  strings:
    $key_2e86 = { 79 f4 [2] 4b d6 [2] 4d e3 [2] 63 e3 [2] 5c ff }

  condition:
    any of them
}