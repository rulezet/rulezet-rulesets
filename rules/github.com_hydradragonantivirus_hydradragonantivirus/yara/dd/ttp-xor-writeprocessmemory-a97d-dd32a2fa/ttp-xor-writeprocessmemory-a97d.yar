rule TTP_XOR_WriteProcessMemory_a97d {
  strings:
    $key_a97d = { fe 0f [2] cc 2d [2] ca 18 [2] e4 18 [2] db 04 }

  condition:
    any of them
}