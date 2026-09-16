rule TTP_XOR_WriteProcessMemory_2565 {
  strings:
    $key_2565 = { 72 17 [2] 40 35 [2] 46 00 [2] 68 00 [2] 57 1c }

  condition:
    any of them
}