rule TTP_XOR_WriteProcessMemory_348f {
  strings:
    $key_348f = { 63 fd [2] 51 df [2] 57 ea [2] 79 ea [2] 46 f6 }

  condition:
    any of them
}