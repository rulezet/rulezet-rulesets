rule TTP_XOR_WriteProcessMemory_af0f {
  strings:
    $key_af0f = { f8 7d [2] ca 5f [2] cc 6a [2] e2 6a [2] dd 76 }

  condition:
    any of them
}