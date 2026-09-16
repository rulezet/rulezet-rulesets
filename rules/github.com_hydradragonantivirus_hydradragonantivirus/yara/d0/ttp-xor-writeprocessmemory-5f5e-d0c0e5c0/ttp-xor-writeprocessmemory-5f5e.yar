rule TTP_XOR_WriteProcessMemory_5f5e {
  strings:
    $key_5f5e = { 08 2c [2] 3a 0e [2] 3c 3b [2] 12 3b [2] 2d 27 }

  condition:
    any of them
}