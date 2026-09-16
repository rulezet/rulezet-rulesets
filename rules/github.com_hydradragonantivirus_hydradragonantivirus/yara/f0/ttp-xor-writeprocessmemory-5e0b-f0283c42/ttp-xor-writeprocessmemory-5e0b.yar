rule TTP_XOR_WriteProcessMemory_5e0b {
  strings:
    $key_5e0b = { 09 79 [2] 3b 5b [2] 3d 6e [2] 13 6e [2] 2c 72 }

  condition:
    any of them
}