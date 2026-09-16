rule TTP_XOR_WriteProcessMemory_f0ed {
  strings:
    $key_f0ed = { a7 9f [2] 95 bd [2] 93 88 [2] bd 88 [2] 82 94 }

  condition:
    any of them
}