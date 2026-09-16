rule TTP_XOR_WriteProcessMemory_f01e {
  strings:
    $key_f01e = { a7 6c [2] 95 4e [2] 93 7b [2] bd 7b [2] 82 67 }

  condition:
    any of them
}