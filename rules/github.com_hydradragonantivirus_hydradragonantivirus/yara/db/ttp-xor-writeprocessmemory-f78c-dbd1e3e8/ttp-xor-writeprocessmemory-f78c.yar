rule TTP_XOR_WriteProcessMemory_f78c {
  strings:
    $key_f78c = { a0 fe [2] 92 dc [2] 94 e9 [2] ba e9 [2] 85 f5 }

  condition:
    any of them
}