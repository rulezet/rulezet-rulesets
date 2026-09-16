rule TTP_XOR_WriteProcessMemory_33f3 {
  strings:
    $key_33f3 = { 64 81 [2] 56 a3 [2] 50 96 [2] 7e 96 [2] 41 8a }

  condition:
    any of them
}