rule TTP_XOR_WriteProcessMemory_6166 {
  strings:
    $key_6166 = { 36 14 [2] 04 36 [2] 02 03 [2] 2c 03 [2] 13 1f }

  condition:
    any of them
}