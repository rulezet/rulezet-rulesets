rule TTP_XOR_WriteProcessMemory_5f21 {
  strings:
    $key_5f21 = { 08 53 [2] 3a 71 [2] 3c 44 [2] 12 44 [2] 2d 58 }

  condition:
    any of them
}