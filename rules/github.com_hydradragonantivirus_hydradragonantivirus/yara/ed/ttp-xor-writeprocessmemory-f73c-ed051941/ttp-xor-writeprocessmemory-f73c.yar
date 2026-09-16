rule TTP_XOR_WriteProcessMemory_f73c {
  strings:
    $key_f73c = { a0 4e [2] 92 6c [2] 94 59 [2] ba 59 [2] 85 45 }

  condition:
    any of them
}