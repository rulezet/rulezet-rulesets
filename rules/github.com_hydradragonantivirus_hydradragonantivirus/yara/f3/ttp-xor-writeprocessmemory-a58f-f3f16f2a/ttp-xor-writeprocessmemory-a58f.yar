rule TTP_XOR_WriteProcessMemory_a58f {
  strings:
    $key_a58f = { f2 fd [2] c0 df [2] c6 ea [2] e8 ea [2] d7 f6 }

  condition:
    any of them
}