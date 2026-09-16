rule TTP_XOR_WriteProcessMemory_7f76 {
  strings:
    $key_7f76 = { 28 04 [2] 1a 26 [2] 1c 13 [2] 32 13 [2] 0d 0f }

  condition:
    any of them
}