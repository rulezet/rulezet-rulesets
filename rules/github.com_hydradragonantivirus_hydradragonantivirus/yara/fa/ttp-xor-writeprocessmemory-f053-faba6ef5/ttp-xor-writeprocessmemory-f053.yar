rule TTP_XOR_WriteProcessMemory_f053 {
  strings:
    $key_f053 = { a7 21 [2] 95 03 [2] 93 36 [2] bd 36 [2] 82 2a }

  condition:
    any of them
}