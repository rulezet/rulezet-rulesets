rule TTP_XOR_WriteProcessMemory_804b {
  strings:
    $key_804b = { d7 39 [2] e5 1b [2] e3 2e [2] cd 2e [2] f2 32 }

  condition:
    any of them
}