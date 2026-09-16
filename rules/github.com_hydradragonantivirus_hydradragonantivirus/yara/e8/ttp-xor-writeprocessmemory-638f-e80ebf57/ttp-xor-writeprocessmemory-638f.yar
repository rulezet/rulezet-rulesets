rule TTP_XOR_WriteProcessMemory_638f {
  strings:
    $key_638f = { 34 fd [2] 06 df [2] 00 ea [2] 2e ea [2] 11 f6 }

  condition:
    any of them
}