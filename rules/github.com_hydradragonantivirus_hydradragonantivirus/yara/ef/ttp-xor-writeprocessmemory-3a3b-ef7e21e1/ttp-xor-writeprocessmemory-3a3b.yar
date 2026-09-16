rule TTP_XOR_WriteProcessMemory_3a3b {
  strings:
    $key_3a3b = { 6d 49 [2] 5f 6b [2] 59 5e [2] 77 5e [2] 48 42 }

  condition:
    any of them
}