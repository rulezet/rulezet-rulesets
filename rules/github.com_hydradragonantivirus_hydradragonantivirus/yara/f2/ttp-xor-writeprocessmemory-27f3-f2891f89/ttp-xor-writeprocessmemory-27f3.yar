rule TTP_XOR_WriteProcessMemory_27f3 {
  strings:
    $key_27f3 = { 70 81 [2] 42 a3 [2] 44 96 [2] 6a 96 [2] 55 8a }

  condition:
    any of them
}