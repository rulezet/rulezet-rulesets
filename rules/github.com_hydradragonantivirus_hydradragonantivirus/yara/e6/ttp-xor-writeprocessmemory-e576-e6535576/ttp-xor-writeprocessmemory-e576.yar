rule TTP_XOR_WriteProcessMemory_e576 {
  strings:
    $key_e576 = { b2 04 [2] 80 26 [2] 86 13 [2] a8 13 [2] 97 0f }

  condition:
    any of them
}