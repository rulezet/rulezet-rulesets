rule TTP_XOR_WriteProcessMemory_f71e {
  strings:
    $key_f71e = { a0 6c [2] 92 4e [2] 94 7b [2] ba 7b [2] 85 67 }

  condition:
    any of them
}