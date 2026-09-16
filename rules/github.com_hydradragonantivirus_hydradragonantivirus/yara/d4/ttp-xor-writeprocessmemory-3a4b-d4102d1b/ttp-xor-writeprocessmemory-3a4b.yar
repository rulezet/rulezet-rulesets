rule TTP_XOR_WriteProcessMemory_3a4b {
  strings:
    $key_3a4b = { 6d 39 [2] 5f 1b [2] 59 2e [2] 77 2e [2] 48 32 }

  condition:
    any of them
}