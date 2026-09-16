rule TTP_XOR_WriteProcessMemory_f73d {
  strings:
    $key_f73d = { a0 4f [2] 92 6d [2] 94 58 [2] ba 58 [2] 85 44 }

  condition:
    any of them
}