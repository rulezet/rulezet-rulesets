rule TTP_XOR_WriteProcessMemory_6110 {
  strings:
    $key_6110 = { 36 62 [2] 04 40 [2] 02 75 [2] 2c 75 [2] 13 69 }

  condition:
    any of them
}