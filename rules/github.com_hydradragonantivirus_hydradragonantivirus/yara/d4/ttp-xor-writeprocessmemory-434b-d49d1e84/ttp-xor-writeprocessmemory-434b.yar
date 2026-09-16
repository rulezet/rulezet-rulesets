rule TTP_XOR_WriteProcessMemory_434b {
  strings:
    $key_434b = { 14 39 [2] 26 1b [2] 20 2e [2] 0e 2e [2] 31 32 }

  condition:
    any of them
}