rule TTP_XOR_WriteProcessMemory_f7ee {
  strings:
    $key_f7ee = { a0 9c [2] 92 be [2] 94 8b [2] ba 8b [2] 85 97 }

  condition:
    any of them
}