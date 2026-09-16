rule TTP_XOR_WriteProcessMemory_7f4b {
  strings:
    $key_7f4b = { 28 39 [2] 1a 1b [2] 1c 2e [2] 32 2e [2] 0d 32 }

  condition:
    any of them
}