rule TTP_XOR_WriteProcessMemory_444b {
  strings:
    $key_444b = { 13 39 [2] 21 1b [2] 27 2e [2] 09 2e [2] 36 32 }

  condition:
    any of them
}