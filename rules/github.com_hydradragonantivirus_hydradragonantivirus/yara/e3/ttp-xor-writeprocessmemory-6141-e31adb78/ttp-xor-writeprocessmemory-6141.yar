rule TTP_XOR_WriteProcessMemory_6141 {
  strings:
    $key_6141 = { 36 33 [2] 04 11 [2] 02 24 [2] 2c 24 [2] 13 38 }

  condition:
    any of them
}