rule TTP_XOR_WriteProcessMemory_5176 {
  strings:
    $key_5176 = { 06 04 [2] 34 26 [2] 32 13 [2] 1c 13 [2] 23 0f }

  condition:
    any of them
}