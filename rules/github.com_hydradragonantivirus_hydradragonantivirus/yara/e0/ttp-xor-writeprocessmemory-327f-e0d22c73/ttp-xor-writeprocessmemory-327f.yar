rule TTP_XOR_WriteProcessMemory_327f {
  strings:
    $key_327f = { 65 0d [2] 57 2f [2] 51 1a [2] 7f 1a [2] 40 06 }

  condition:
    any of them
}