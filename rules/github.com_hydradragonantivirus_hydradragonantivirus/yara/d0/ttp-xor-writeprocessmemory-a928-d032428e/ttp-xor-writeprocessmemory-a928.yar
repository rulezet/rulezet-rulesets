rule TTP_XOR_WriteProcessMemory_a928 {
  strings:
    $key_a928 = { fe 5a [2] cc 78 [2] ca 4d [2] e4 4d [2] db 51 }

  condition:
    any of them
}