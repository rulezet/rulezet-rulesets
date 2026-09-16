rule TTP_XOR_WriteProcessMemory_f71d {
  strings:
    $key_f71d = { a0 6f [2] 92 4d [2] 94 78 [2] ba 78 [2] 85 64 }

  condition:
    any of them
}