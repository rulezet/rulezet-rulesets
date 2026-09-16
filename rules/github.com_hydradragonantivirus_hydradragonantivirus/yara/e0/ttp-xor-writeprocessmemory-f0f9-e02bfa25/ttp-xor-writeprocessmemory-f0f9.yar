rule TTP_XOR_WriteProcessMemory_f0f9 {
  strings:
    $key_f0f9 = { a7 8b [2] 95 a9 [2] 93 9c [2] bd 9c [2] 82 80 }

  condition:
    any of them
}