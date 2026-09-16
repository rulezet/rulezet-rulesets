rule TTP_XOR_WriteProcessMemory_966b {
  strings:
    $key_966b = { c1 19 [2] f3 3b [2] f5 0e [2] db 0e [2] e4 12 }

  condition:
    any of them
}