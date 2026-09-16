rule TTP_XOR_WriteProcessMemory_350b {
  strings:
    $key_350b = { 62 79 [2] 50 5b [2] 56 6e [2] 78 6e [2] 47 72 }

  condition:
    any of them
}