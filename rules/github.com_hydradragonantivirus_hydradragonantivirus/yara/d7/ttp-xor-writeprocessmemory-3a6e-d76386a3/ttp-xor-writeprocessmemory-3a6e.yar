rule TTP_XOR_WriteProcessMemory_3a6e {
  strings:
    $key_3a6e = { 6d 1c [2] 5f 3e [2] 59 0b [2] 77 0b [2] 48 17 }

  condition:
    any of them
}