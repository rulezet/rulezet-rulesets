rule TTP_XOR_WriteProcessMemory_a92d {
  strings:
    $key_a92d = { fe 5f [2] cc 7d [2] ca 48 [2] e4 48 [2] db 54 }

  condition:
    any of them
}