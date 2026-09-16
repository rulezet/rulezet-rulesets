rule TTP_XOR_WriteProcessMemory_5155 {
  strings:
    $key_5155 = { 06 27 [2] 34 05 [2] 32 30 [2] 1c 30 [2] 23 2c }

  condition:
    any of them
}