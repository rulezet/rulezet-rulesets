rule TTP_XOR_WriteProcessMemory_6100 {
  strings:
    $key_6100 = { 36 72 [2] 04 50 [2] 02 65 [2] 2c 65 [2] 13 79 }

  condition:
    any of them
}