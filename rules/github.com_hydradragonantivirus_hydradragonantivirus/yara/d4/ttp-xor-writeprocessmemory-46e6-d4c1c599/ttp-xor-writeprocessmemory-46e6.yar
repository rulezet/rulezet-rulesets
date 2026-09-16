rule TTP_XOR_WriteProcessMemory_46e6 {
  strings:
    $key_46e6 = { 11 94 [2] 23 b6 [2] 25 83 [2] 0b 83 [2] 34 9f }

  condition:
    any of them
}