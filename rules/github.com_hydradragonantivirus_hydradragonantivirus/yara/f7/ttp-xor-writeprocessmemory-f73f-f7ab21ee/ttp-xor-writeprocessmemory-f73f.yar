rule TTP_XOR_WriteProcessMemory_f73f {
  strings:
    $key_f73f = { a0 4d [2] 92 6f [2] 94 5a [2] ba 5a [2] 85 46 }

  condition:
    any of them
}