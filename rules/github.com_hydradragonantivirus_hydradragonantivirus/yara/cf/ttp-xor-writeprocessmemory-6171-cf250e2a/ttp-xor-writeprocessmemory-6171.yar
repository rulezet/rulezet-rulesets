rule TTP_XOR_WriteProcessMemory_6171 {
  strings:
    $key_6171 = { 36 03 [2] 04 21 [2] 02 14 [2] 2c 14 [2] 13 08 }

  condition:
    any of them
}