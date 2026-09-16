rule TTP_XOR_WriteProcessMemory_5f0e {
  strings:
    $key_5f0e = { 08 7c [2] 3a 5e [2] 3c 6b [2] 12 6b [2] 2d 77 }

  condition:
    any of them
}