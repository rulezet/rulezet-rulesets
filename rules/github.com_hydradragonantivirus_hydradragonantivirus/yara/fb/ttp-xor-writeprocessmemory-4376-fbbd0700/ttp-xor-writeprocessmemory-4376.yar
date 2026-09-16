rule TTP_XOR_WriteProcessMemory_4376 {
  strings:
    $key_4376 = { 14 04 [2] 26 26 [2] 20 13 [2] 0e 13 [2] 31 0f }

  condition:
    any of them
}