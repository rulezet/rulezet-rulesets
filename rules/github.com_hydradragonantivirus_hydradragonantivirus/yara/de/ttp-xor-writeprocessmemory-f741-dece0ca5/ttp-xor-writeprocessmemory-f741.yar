rule TTP_XOR_WriteProcessMemory_f741 {
  strings:
    $key_f741 = { a0 33 [2] 92 11 [2] 94 24 [2] ba 24 [2] 85 38 }

  condition:
    any of them
}