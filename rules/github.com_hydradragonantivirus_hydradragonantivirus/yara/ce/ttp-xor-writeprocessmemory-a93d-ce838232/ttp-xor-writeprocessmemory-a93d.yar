rule TTP_XOR_WriteProcessMemory_a93d {
  strings:
    $key_a93d = { fe 4f [2] cc 6d [2] ca 58 [2] e4 58 [2] db 44 }

  condition:
    any of them
}