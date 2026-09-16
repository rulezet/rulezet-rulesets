rule TTP_XOR_WriteProcessMemory_f00e {
  strings:
    $key_f00e = { a7 7c [2] 95 5e [2] 93 6b [2] bd 6b [2] 82 77 }

  condition:
    any of them
}