rule TTP_XOR_WriteProcessMemory_f68c {
  strings:
    $key_f68c = { a1 fe [2] 93 dc [2] 95 e9 [2] bb e9 [2] 84 f5 }

  condition:
    any of them
}