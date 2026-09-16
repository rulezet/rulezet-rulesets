rule TTP_XOR_WriteProcessMemory_572e {
  strings:
    $key_572e = { 00 5c [2] 32 7e [2] 34 4b [2] 1a 4b [2] 25 57 }

  condition:
    any of them
}