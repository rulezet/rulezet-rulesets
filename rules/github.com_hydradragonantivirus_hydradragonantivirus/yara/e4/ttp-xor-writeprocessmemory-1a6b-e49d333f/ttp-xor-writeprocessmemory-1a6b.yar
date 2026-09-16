rule TTP_XOR_WriteProcessMemory_1a6b {
  strings:
    $key_1a6b = { 4d 19 [2] 7f 3b [2] 79 0e [2] 57 0e [2] 68 12 }

  condition:
    any of them
}