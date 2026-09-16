rule TTP_XOR_WriteProcessMemory_69c2 {
  strings:
    $key_69c2 = { 3e b0 [2] 0c 92 [2] 0a a7 [2] 24 a7 [2] 1b bb }

  condition:
    any of them
}