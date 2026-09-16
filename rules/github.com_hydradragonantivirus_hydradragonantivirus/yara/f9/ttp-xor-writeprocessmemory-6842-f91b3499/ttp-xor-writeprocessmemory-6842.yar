rule TTP_XOR_WriteProcessMemory_6842 {
  strings:
    $key_6842 = { 3f 30 [2] 0d 12 [2] 0b 27 [2] 25 27 [2] 1a 3b }

  condition:
    any of them
}