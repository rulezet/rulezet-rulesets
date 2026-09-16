rule TTP_XOR_WriteProcessMemory_5e2b {
  strings:
    $key_5e2b = { 09 59 [2] 3b 7b [2] 3d 4e [2] 13 4e [2] 2c 52 }

  condition:
    any of them
}