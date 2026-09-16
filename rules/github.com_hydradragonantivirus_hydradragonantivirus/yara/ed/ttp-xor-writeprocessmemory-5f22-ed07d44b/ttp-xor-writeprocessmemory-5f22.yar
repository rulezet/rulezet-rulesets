rule TTP_XOR_WriteProcessMemory_5f22 {
  strings:
    $key_5f22 = { 08 50 [2] 3a 72 [2] 3c 47 [2] 12 47 [2] 2d 5b }

  condition:
    any of them
}