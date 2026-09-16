rule TTP_XOR_WriteProcessMemory_a946 {
  strings:
    $key_a946 = { fe 34 [2] cc 16 [2] ca 23 [2] e4 23 [2] db 3f }

  condition:
    any of them
}