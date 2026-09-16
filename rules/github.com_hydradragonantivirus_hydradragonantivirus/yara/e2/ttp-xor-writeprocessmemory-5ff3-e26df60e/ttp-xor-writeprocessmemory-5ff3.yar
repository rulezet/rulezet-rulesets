rule TTP_XOR_WriteProcessMemory_5ff3 {
  strings:
    $key_5ff3 = { 08 81 [2] 3a a3 [2] 3c 96 [2] 12 96 [2] 2d 8a }

  condition:
    any of them
}