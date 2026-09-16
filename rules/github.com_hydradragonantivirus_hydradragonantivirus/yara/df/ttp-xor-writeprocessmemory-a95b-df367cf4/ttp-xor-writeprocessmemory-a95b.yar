rule TTP_XOR_WriteProcessMemory_a95b {
  strings:
    $key_a95b = { fe 29 [2] cc 0b [2] ca 3e [2] e4 3e [2] db 22 }

  condition:
    any of them
}