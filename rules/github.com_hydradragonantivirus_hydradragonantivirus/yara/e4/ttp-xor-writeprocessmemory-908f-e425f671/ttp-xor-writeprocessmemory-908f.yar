rule TTP_XOR_WriteProcessMemory_908f {
  strings:
    $key_908f = { c7 fd [2] f5 df [2] f3 ea [2] dd ea [2] e2 f6 }

  condition:
    any of them
}