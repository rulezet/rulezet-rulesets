rule TTP_XOR_WriteProcessMemory_6863 {
  strings:
    $key_6863 = { 3f 11 [2] 0d 33 [2] 0b 06 [2] 25 06 [2] 1a 1a }

  condition:
    any of them
}