rule TTP_XOR_WriteProcessMemory_f01b {
  strings:
    $key_f01b = { a7 69 [2] 95 4b [2] 93 7e [2] bd 7e [2] 82 62 }

  condition:
    any of them
}