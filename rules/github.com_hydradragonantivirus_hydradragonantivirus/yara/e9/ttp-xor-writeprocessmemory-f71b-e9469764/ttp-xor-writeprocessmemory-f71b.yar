rule TTP_XOR_WriteProcessMemory_f71b {
  strings:
    $key_f71b = { a0 69 [2] 92 4b [2] 94 7e [2] ba 7e [2] 85 62 }

  condition:
    any of them
}