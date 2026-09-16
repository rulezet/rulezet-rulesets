rule TTP_XOR_WriteProcessMemory_6376 {
  strings:
    $key_6376 = { 34 04 [2] 06 26 [2] 00 13 [2] 2e 13 [2] 11 0f }

  condition:
    any of them
}