rule TTP_XOR_WriteProcessMemory_5f1b {
  strings:
    $key_5f1b = { 08 69 [2] 3a 4b [2] 3c 7e [2] 12 7e [2] 2d 62 }

  condition:
    any of them
}