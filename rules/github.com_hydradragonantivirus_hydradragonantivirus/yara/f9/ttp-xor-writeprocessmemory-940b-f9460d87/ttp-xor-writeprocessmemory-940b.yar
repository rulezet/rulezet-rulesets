rule TTP_XOR_WriteProcessMemory_940b {
  strings:
    $key_940b = { c3 79 [2] f1 5b [2] f7 6e [2] d9 6e [2] e6 72 }

  condition:
    any of them
}