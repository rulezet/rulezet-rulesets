rule TTP_XOR_WriteProcessMemory_55f6 {
  strings:
    $key_55f6 = { 02 84 [2] 30 a6 [2] 36 93 [2] 18 93 [2] 27 8f }

  condition:
    any of them
}