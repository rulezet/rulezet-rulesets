rule TTP_XOR_WriteProcessMemory_6116 {
  strings:
    $key_6116 = { 36 64 [2] 04 46 [2] 02 73 [2] 2c 73 [2] 13 6f }

  condition:
    any of them
}