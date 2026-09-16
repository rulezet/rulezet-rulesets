rule TTP_XOR_WriteProcessMemory_56f3 {
  strings:
    $key_56f3 = { 01 81 [2] 33 a3 [2] 35 96 [2] 1b 96 [2] 24 8a }

  condition:
    any of them
}