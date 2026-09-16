rule TTP_XOR_WriteProcessMemory_f761 {
  strings:
    $key_f761 = { a0 13 [2] 92 31 [2] 94 04 [2] ba 04 [2] 85 18 }

  condition:
    any of them
}