rule TTP_XOR_WriteProcessMemory_5565 {
  strings:
    $key_5565 = { 02 17 [2] 30 35 [2] 36 00 [2] 18 00 [2] 27 1c }

  condition:
    any of them
}