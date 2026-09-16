rule TTP_XOR_WriteProcessMemory_f0ba {
  strings:
    $key_f0ba = { a7 c8 [2] 95 ea [2] 93 df [2] bd df [2] 82 c3 }

  condition:
    any of them
}