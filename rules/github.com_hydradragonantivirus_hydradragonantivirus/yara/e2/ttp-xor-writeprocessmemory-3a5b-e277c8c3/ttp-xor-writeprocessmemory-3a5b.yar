rule TTP_XOR_WriteProcessMemory_3a5b {
  strings:
    $key_3a5b = { 6d 29 [2] 5f 0b [2] 59 3e [2] 77 3e [2] 48 22 }

  condition:
    any of them
}