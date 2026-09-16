rule TTP_XOR_WriteProcessMemory_5f23 {
  strings:
    $key_5f23 = { 08 51 [2] 3a 73 [2] 3c 46 [2] 12 46 [2] 2d 5a }

  condition:
    any of them
}