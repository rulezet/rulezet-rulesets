rule TTP_XOR_WriteProcessMemory_a9ee {
  strings:
    $key_a9ee = { fe 9c [2] cc be [2] ca 8b [2] e4 8b [2] db 97 }

  condition:
    any of them
}