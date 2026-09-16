rule TTP_XOR_WriteProcessMemory_7d0e {
  strings:
    $key_7d0e = { 2a 7c [2] 18 5e [2] 1e 6b [2] 30 6b [2] 0f 77 }

  condition:
    any of them
}