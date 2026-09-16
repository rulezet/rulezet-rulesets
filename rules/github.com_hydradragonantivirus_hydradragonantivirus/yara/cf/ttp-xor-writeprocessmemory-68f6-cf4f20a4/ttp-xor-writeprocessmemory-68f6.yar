rule TTP_XOR_WriteProcessMemory_68f6 {
  strings:
    $key_68f6 = { 3f 84 [2] 0d a6 [2] 0b 93 [2] 25 93 [2] 1a 8f }

  condition:
    any of them
}