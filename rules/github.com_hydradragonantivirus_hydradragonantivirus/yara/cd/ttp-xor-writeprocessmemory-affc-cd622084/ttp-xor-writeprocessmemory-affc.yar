rule TTP_XOR_WriteProcessMemory_affc {
  strings:
    $key_affc = { f8 8e [2] ca ac [2] cc 99 [2] e2 99 [2] dd 85 }

  condition:
    any of them
}