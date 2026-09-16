rule TTP_XOR_WriteProcessMemory_64f3 {
  strings:
    $key_64f3 = { 33 81 [2] 01 a3 [2] 07 96 [2] 29 96 [2] 16 8a }

  condition:
    any of them
}