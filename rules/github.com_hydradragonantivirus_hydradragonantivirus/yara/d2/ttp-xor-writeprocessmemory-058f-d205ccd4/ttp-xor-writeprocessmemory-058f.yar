rule TTP_XOR_WriteProcessMemory_058f {
  strings:
    $key_058f = { 52 fd [2] 60 df [2] 66 ea [2] 48 ea [2] 77 f6 }

  condition:
    any of them
}