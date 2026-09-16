rule TTP_XOR_WriteProcessMemory_a18f {
  strings:
    $key_a18f = { f6 fd [2] c4 df [2] c2 ea [2] ec ea [2] d3 f6 }

  condition:
    any of them
}