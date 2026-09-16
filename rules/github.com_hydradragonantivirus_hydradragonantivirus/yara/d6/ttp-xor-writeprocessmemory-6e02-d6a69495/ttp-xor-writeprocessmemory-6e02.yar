rule TTP_XOR_WriteProcessMemory_6e02 {
  strings:
    $key_6e02 = { 39 70 [2] 0b 52 [2] 0d 67 [2] 23 67 [2] 1c 7b }

  condition:
    any of them
}