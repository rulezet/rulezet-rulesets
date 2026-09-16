rule TTP_XOR_WriteProcessMemory_3a7b {
  strings:
    $key_3a7b = { 6d 09 [2] 5f 2b [2] 59 1e [2] 77 1e [2] 48 02 }

  condition:
    any of them
}