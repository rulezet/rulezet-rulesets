rule TTP_XOR_WriteProcessMemory_a90e {
  strings:
    $key_a90e = { fe 7c [2] cc 5e [2] ca 6b [2] e4 6b [2] db 77 }

  condition:
    any of them
}