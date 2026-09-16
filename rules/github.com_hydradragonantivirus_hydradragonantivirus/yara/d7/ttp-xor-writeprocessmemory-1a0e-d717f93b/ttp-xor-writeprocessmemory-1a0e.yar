rule TTP_XOR_WriteProcessMemory_1a0e {
  strings:
    $key_1a0e = { 4d 7c [2] 7f 5e [2] 79 6b [2] 57 6b [2] 68 77 }

  condition:
    any of them
}