rule TTP_XOR_WriteProcessMemory_a92b {
  strings:
    $key_a92b = { fe 59 [2] cc 7b [2] ca 4e [2] e4 4e [2] db 52 }

  condition:
    any of them
}