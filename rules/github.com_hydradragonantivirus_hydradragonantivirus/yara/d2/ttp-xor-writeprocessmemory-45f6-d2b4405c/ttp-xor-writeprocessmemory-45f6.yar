rule TTP_XOR_WriteProcessMemory_45f6 {
  strings:
    $key_45f6 = { 12 84 [2] 20 a6 [2] 26 93 [2] 08 93 [2] 37 8f }

  condition:
    any of them
}