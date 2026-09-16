rule TTP_XOR_WriteProcessMemory_1a4b {
  strings:
    $key_1a4b = { 4d 39 [2] 7f 1b [2] 79 2e [2] 57 2e [2] 68 32 }

  condition:
    any of them
}