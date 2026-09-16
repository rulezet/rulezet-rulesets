rule TTP_XOR_WriteProcessMemory_4e86 {
  strings:
    $key_4e86 = { 19 f4 [2] 2b d6 [2] 2d e3 [2] 03 e3 [2] 3c ff }

  condition:
    any of them
}