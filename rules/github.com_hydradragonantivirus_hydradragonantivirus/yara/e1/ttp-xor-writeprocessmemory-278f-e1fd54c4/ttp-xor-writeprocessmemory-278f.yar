rule TTP_XOR_WriteProcessMemory_278f {
  strings:
    $key_278f = { 70 fd [2] 42 df [2] 44 ea [2] 6a ea [2] 55 f6 }

  condition:
    any of them
}