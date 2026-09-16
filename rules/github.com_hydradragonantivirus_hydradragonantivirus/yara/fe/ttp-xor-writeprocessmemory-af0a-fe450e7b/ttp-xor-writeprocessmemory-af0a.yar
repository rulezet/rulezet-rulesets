rule TTP_XOR_WriteProcessMemory_af0a {
  strings:
    $key_af0a = { f8 78 [2] ca 5a [2] cc 6f [2] e2 6f [2] dd 73 }

  condition:
    any of them
}