rule TTP_XOR_WriteProcessMemory_6153 {
  strings:
    $key_6153 = { 36 21 [2] 04 03 [2] 02 36 [2] 2c 36 [2] 13 2a }

  condition:
    any of them
}