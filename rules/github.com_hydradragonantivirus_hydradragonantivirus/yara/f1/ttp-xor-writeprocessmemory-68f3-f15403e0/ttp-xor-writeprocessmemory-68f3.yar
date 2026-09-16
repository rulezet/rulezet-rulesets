rule TTP_XOR_WriteProcessMemory_68f3 {
  strings:
    $key_68f3 = { 3f 81 [2] 0d a3 [2] 0b 96 [2] 25 96 [2] 1a 8a }

  condition:
    any of them
}