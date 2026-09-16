rule TTP_XOR_WriteProcessMemory_afea {
  strings:
    $key_afea = { f8 98 [2] ca ba [2] cc 8f [2] e2 8f [2] dd 93 }

  condition:
    any of them
}