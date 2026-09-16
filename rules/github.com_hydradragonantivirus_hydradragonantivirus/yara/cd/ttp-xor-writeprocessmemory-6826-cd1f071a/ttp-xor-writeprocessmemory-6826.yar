rule TTP_XOR_WriteProcessMemory_6826 {
  strings:
    $key_6826 = { 3f 54 [2] 0d 76 [2] 0b 43 [2] 25 43 [2] 1a 5f }

  condition:
    any of them
}