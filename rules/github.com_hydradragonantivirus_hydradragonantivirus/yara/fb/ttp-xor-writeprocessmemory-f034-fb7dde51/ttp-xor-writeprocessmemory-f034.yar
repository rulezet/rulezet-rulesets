rule TTP_XOR_WriteProcessMemory_f034 {
  strings:
    $key_f034 = { a7 46 [2] 95 64 [2] 93 51 [2] bd 51 [2] 82 4d }

  condition:
    any of them
}