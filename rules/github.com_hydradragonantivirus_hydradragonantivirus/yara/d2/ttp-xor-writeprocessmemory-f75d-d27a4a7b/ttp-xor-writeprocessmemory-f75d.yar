rule TTP_XOR_WriteProcessMemory_f75d {
  strings:
    $key_f75d = { a0 2f [2] 92 0d [2] 94 38 [2] ba 38 [2] 85 24 }

  condition:
    any of them
}