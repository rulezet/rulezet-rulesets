rule TTP_XOR_WriteProcessMemory_358f {
  strings:
    $key_358f = { 62 fd [2] 50 df [2] 56 ea [2] 78 ea [2] 47 f6 }

  condition:
    any of them
}