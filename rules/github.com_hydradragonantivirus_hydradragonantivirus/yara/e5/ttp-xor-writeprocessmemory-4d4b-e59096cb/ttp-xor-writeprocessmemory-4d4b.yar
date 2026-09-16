rule TTP_XOR_WriteProcessMemory_4d4b {
  strings:
    $key_4d4b = { 1a 39 [2] 28 1b [2] 2e 2e [2] 00 2e [2] 3f 32 }

  condition:
    any of them
}