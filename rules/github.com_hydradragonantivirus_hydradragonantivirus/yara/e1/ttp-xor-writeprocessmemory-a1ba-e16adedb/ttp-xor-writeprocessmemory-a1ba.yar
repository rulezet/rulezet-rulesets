rule TTP_XOR_WriteProcessMemory_a1ba {
  strings:
    $key_a1ba = { f6 c8 [2] c4 ea [2] c2 df [2] ec df [2] d3 c3 }

  condition:
    any of them
}