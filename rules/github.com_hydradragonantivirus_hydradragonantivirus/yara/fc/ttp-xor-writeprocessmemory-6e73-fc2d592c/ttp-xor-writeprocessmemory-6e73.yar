rule TTP_XOR_WriteProcessMemory_6e73 {
  strings:
    $key_6e73 = { 39 01 [2] 0b 23 [2] 0d 16 [2] 23 16 [2] 1c 0a }

  condition:
    any of them
}