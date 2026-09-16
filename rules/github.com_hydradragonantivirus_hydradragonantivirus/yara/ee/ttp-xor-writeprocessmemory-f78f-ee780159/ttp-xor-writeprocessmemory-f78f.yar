rule TTP_XOR_WriteProcessMemory_f78f {
  strings:
    $key_f78f = { a0 fd [2] 92 df [2] 94 ea [2] ba ea [2] 85 f6 }

  condition:
    any of them
}