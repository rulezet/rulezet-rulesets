rule TTP_XOR_WriteProcessMemory_f76f {
  strings:
    $key_f76f = { a0 1d [2] 92 3f [2] 94 0a [2] ba 0a [2] 85 16 }

  condition:
    any of them
}