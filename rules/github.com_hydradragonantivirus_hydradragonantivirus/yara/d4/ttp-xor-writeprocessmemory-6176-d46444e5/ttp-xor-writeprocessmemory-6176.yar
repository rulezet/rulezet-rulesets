rule TTP_XOR_WriteProcessMemory_6176 {
  strings:
    $key_6176 = { 36 04 [2] 04 26 [2] 02 13 [2] 2c 13 [2] 13 0f }

  condition:
    any of them
}