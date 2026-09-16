rule TTP_XOR_WriteProcessMemory_628f {
  strings:
    $key_628f = { 35 fd [2] 07 df [2] 01 ea [2] 2f ea [2] 10 f6 }

  condition:
    any of them
}