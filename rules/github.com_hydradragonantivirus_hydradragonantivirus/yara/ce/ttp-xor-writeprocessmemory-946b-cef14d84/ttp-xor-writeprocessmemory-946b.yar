rule TTP_XOR_WriteProcessMemory_946b {
  strings:
    $key_946b = { c3 19 [2] f1 3b [2] f7 0e [2] d9 0e [2] e6 12 }

  condition:
    any of them
}