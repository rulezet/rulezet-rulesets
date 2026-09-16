rule TTP_XOR_WriteProcessMemory_a960 {
  strings:
    $key_a960 = { fe 12 [2] cc 30 [2] ca 05 [2] e4 05 [2] db 19 }

  condition:
    any of them
}