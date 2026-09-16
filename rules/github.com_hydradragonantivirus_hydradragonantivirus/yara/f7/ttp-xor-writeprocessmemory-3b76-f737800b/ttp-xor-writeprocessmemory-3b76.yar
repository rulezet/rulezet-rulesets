rule TTP_XOR_WriteProcessMemory_3b76 {
  strings:
    $key_3b76 = { 6c 04 [2] 5e 26 [2] 58 13 [2] 76 13 [2] 49 0f }

  condition:
    any of them
}