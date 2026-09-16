rule TTP_XOR_WriteProcessMemory_404b {
  strings:
    $key_404b = { 17 39 [2] 25 1b [2] 23 2e [2] 0d 2e [2] 32 32 }

  condition:
    any of them
}