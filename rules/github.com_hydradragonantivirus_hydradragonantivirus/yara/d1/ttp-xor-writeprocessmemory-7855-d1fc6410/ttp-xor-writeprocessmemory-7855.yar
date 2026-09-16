rule TTP_XOR_WriteProcessMemory_7855 {
  strings:
    $key_7855 = { 2f 27 [2] 1d 05 [2] 1b 30 [2] 35 30 [2] 0a 2c }

  condition:
    any of them
}