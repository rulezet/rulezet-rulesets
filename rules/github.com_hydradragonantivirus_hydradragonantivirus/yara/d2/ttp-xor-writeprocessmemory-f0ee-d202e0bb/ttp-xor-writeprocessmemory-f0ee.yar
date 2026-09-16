rule TTP_XOR_WriteProcessMemory_f0ee {
  strings:
    $key_f0ee = { a7 9c [2] 95 be [2] 93 8b [2] bd 8b [2] 82 97 }

  condition:
    any of them
}