rule TTP_XOR_WriteProcessMemory_650e {
  strings:
    $key_650e = { 32 7c [2] 00 5e [2] 06 6b [2] 28 6b [2] 17 77 }

  condition:
    any of them
}