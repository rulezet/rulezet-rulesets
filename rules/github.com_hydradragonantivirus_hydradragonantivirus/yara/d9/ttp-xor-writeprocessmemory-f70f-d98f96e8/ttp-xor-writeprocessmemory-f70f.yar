rule TTP_XOR_WriteProcessMemory_f70f {
  strings:
    $key_f70f = { a0 7d [2] 92 5f [2] 94 6a [2] ba 6a [2] 85 76 }

  condition:
    any of them
}