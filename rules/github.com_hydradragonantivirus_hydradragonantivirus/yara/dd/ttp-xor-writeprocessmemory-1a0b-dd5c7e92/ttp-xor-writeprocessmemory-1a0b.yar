rule TTP_XOR_WriteProcessMemory_1a0b {
  strings:
    $key_1a0b = { 4d 79 [2] 7f 5b [2] 79 6e [2] 57 6e [2] 68 72 }

  condition:
    any of them
}