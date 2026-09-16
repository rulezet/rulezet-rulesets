rule TTP_XOR_WriteProcessMemory_6f76 {
  strings:
    $key_6f76 = { 38 04 [2] 0a 26 [2] 0c 13 [2] 22 13 [2] 1d 0f }

  condition:
    any of them
}