rule TTP_XOR_WriteProcessMemory_5f20 {
  strings:
    $key_5f20 = { 08 52 [2] 3a 70 [2] 3c 45 [2] 12 45 [2] 2d 59 }

  condition:
    any of them
}