rule TTP_XOR_WriteProcessMemory_570e {
  strings:
    $key_570e = { 00 7c [2] 32 5e [2] 34 6b [2] 1a 6b [2] 25 77 }

  condition:
    any of them
}