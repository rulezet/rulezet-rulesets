rule TTP_XOR_WriteProcessMemory_af5f {
  strings:
    $key_af5f = { f8 2d [2] ca 0f [2] cc 3a [2] e2 3a [2] dd 26 }

  condition:
    any of them
}