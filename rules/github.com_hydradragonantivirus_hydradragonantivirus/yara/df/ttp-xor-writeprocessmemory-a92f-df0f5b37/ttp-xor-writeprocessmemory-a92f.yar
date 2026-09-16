rule TTP_XOR_WriteProcessMemory_a92f {
  strings:
    $key_a92f = { fe 5d [2] cc 7f [2] ca 4a [2] e4 4a [2] db 56 }

  condition:
    any of them
}