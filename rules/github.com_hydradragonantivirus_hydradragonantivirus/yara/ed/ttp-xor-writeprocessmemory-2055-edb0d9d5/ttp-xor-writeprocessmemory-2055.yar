rule TTP_XOR_WriteProcessMemory_2055 {
  strings:
    $key_2055 = { 77 27 [2] 45 05 [2] 43 30 [2] 6d 30 [2] 52 2c }

  condition:
    any of them
}