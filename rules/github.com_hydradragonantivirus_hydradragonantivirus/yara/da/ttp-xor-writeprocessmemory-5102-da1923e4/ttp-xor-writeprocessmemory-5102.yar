rule TTP_XOR_WriteProcessMemory_5102 {
  strings:
    $key_5102 = { 06 70 [2] 34 52 [2] 32 67 [2] 1c 67 [2] 23 7b }

  condition:
    any of them
}