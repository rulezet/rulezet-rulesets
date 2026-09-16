rule TTP_XOR_WriteProcessMemory_6e0e {
  strings:
    $key_6e0e = { 39 7c [2] 0b 5e [2] 0d 6b [2] 23 6b [2] 1c 77 }

  condition:
    any of them
}