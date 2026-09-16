rule TTP_XOR_WriteProcessMemory_5f49 {
  strings:
    $key_5f49 = { 08 3b [2] 3a 19 [2] 3c 2c [2] 12 2c [2] 2d 30 }

  condition:
    any of them
}