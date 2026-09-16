rule TTP_XOR_WriteProcessMemory_a96d {
  strings:
    $key_a96d = { fe 1f [2] cc 3d [2] ca 08 [2] e4 08 [2] db 14 }

  condition:
    any of them
}