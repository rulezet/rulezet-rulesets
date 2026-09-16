rule TTP_XOR_WriteProcessMemory_a95d {
  strings:
    $key_a95d = { fe 2f [2] cc 0d [2] ca 38 [2] e4 38 [2] db 24 }

  condition:
    any of them
}