rule TTP_XOR_WriteProcessMemory_b6ba {
  strings:
    $key_b6ba = { e1 c8 [2] d3 ea [2] d5 df [2] fb df [2] c4 c3 }

  condition:
    any of them
}