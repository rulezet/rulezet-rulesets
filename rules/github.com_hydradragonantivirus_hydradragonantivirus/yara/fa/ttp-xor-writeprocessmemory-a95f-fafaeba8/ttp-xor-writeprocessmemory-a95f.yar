rule TTP_XOR_WriteProcessMemory_a95f {
  strings:
    $key_a95f = { fe 2d [2] cc 0f [2] ca 3a [2] e4 3a [2] db 26 }

  condition:
    any of them
}