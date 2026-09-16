rule TTP_XOR_WriteProcessMemory_6105 {
  strings:
    $key_6105 = { 36 77 [2] 04 55 [2] 02 60 [2] 2c 60 [2] 13 7c }

  condition:
    any of them
}