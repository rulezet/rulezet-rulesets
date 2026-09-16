rule TTP_XOR_WriteProcessMemory_078f {
  strings:
    $key_078f = { 50 fd [2] 62 df [2] 64 ea [2] 4a ea [2] 75 f6 }

  condition:
    any of them
}