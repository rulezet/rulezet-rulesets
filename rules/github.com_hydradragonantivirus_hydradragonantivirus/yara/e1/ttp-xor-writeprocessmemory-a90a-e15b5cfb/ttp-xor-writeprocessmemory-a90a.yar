rule TTP_XOR_WriteProcessMemory_a90a {
  strings:
    $key_a90a = { fe 78 [2] cc 5a [2] ca 6f [2] e4 6f [2] db 73 }

  condition:
    any of them
}