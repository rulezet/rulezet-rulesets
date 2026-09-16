rule TTP_XOR_WriteProcessMemory_6150 {
  strings:
    $key_6150 = { 36 22 [2] 04 00 [2] 02 35 [2] 2c 35 [2] 13 29 }

  condition:
    any of them
}