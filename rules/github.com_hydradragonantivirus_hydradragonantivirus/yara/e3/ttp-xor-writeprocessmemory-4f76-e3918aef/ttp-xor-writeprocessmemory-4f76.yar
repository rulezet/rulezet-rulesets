rule TTP_XOR_WriteProcessMemory_4f76 {
  strings:
    $key_4f76 = { 18 04 [2] 2a 26 [2] 2c 13 [2] 02 13 [2] 3d 0f }

  condition:
    any of them
}