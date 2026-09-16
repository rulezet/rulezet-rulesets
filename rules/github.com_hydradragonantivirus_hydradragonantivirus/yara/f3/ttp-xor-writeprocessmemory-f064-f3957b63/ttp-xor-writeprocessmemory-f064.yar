rule TTP_XOR_WriteProcessMemory_f064 {
  strings:
    $key_f064 = { a7 16 [2] 95 34 [2] 93 01 [2] bd 01 [2] 82 1d }

  condition:
    any of them
}