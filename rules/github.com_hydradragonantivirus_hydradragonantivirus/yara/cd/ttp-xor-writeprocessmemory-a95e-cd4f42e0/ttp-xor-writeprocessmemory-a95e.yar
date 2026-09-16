rule TTP_XOR_WriteProcessMemory_a95e {
  strings:
    $key_a95e = { fe 2c [2] cc 0e [2] ca 3b [2] e4 3b [2] db 27 }

  condition:
    any of them
}