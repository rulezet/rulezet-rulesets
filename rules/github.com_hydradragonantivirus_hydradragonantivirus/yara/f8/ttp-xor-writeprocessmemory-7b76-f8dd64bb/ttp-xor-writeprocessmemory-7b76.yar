rule TTP_XOR_WriteProcessMemory_7b76 {
  strings:
    $key_7b76 = { 2c 04 [2] 1e 26 [2] 18 13 [2] 36 13 [2] 09 0f }

  condition:
    any of them
}