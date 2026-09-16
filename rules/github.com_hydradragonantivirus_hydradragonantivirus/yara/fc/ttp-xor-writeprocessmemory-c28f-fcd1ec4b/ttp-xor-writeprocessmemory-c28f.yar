rule TTP_XOR_WriteProcessMemory_c28f {
  strings:
    $key_c28f = { 95 fd [2] a7 df [2] a1 ea [2] 8f ea [2] b0 f6 }

  condition:
    any of them
}