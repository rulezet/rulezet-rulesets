rule TTP_XOR_WriteProcessMemory_578f {
  strings:
    $key_578f = { 00 fd [2] 32 df [2] 34 ea [2] 1a ea [2] 25 f6 }

  condition:
    any of them
}