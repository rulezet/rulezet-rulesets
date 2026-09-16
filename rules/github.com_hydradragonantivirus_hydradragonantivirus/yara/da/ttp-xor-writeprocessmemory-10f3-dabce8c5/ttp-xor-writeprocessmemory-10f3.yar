rule TTP_XOR_WriteProcessMemory_10f3 {
  strings:
    $key_10f3 = { 47 81 [2] 75 a3 [2] 73 96 [2] 5d 96 [2] 62 8a }

  condition:
    any of them
}