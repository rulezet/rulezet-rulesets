rule TTP_XOR_WriteProcessMemory_7f49 {
  strings:
    $key_7f49 = { 28 3b [2] 1a 19 [2] 1c 2c [2] 32 2c [2] 0d 30 }

  condition:
    any of them
}