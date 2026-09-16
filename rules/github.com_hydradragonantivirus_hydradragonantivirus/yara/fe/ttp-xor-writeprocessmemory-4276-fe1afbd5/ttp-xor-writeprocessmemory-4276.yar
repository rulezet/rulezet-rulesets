rule TTP_XOR_WriteProcessMemory_4276 {
  strings:
    $key_4276 = { 15 04 [2] 27 26 [2] 21 13 [2] 0f 13 [2] 30 0f }

  condition:
    any of them
}