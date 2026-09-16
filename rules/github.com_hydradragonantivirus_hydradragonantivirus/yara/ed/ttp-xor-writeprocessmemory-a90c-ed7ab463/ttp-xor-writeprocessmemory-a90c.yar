rule TTP_XOR_WriteProcessMemory_a90c {
  strings:
    $key_a90c = { fe 7e [2] cc 5c [2] ca 69 [2] e4 69 [2] db 75 }

  condition:
    any of them
}