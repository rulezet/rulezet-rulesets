rule TTP_XOR_WriteProcessMemory_a94f {
  strings:
    $key_a94f = { fe 3d [2] cc 1f [2] ca 2a [2] e4 2a [2] db 36 }

  condition:
    any of them
}