rule TTP_XOR_WriteProcessMemory_1f0e {
  strings:
    $key_1f0e = { 48 7c [2] 7a 5e [2] 7c 6b [2] 52 6b [2] 6d 77 }

  condition:
    any of them
}