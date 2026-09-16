rule TTP_XOR_WriteProcessMemory_a96a {
  strings:
    $key_a96a = { fe 18 [2] cc 3a [2] ca 0f [2] e4 0f [2] db 13 }

  condition:
    any of them
}