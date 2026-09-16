rule TTP_XOR_WriteProcessMemory_a940 {
  strings:
    $key_a940 = { fe 32 [2] cc 10 [2] ca 25 [2] e4 25 [2] db 39 }

  condition:
    any of them
}