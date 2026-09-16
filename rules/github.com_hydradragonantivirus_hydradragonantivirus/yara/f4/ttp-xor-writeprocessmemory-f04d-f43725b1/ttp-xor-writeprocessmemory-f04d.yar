rule TTP_XOR_WriteProcessMemory_f04d {
  strings:
    $key_f04d = { a7 3f [2] 95 1d [2] 93 28 [2] bd 28 [2] 82 34 }

  condition:
    any of them
}