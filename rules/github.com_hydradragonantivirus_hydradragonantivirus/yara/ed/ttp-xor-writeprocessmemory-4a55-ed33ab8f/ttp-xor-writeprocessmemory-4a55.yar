rule TTP_XOR_WriteProcessMemory_4a55 {
  strings:
    $key_4a55 = { 1d 27 [2] 2f 05 [2] 29 30 [2] 07 30 [2] 38 2c }

  condition:
    any of them
}