rule TTP_XOR_WriteProcessMemory_7986 {
  strings:
    $key_7986 = { 2e f4 [2] 1c d6 [2] 1a e3 [2] 34 e3 [2] 0b ff }

  condition:
    any of them
}