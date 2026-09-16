rule TTP_XOR_WriteProcessMemory_f01c {
  strings:
    $key_f01c = { a7 6e [2] 95 4c [2] 93 79 [2] bd 79 [2] 82 65 }

  condition:
    any of them
}