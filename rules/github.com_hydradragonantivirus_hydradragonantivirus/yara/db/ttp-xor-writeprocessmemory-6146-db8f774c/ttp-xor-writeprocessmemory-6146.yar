rule TTP_XOR_WriteProcessMemory_6146 {
  strings:
    $key_6146 = { 36 34 [2] 04 16 [2] 02 23 [2] 2c 23 [2] 13 3f }

  condition:
    any of them
}