rule TTP_XOR_WriteProcessMemory_f732 {
  strings:
    $key_f732 = { a0 40 [2] 92 62 [2] 94 57 [2] ba 57 [2] 85 4b }

  condition:
    any of them
}