rule TTP_XOR_WriteProcessMemory_d3ba {
  strings:
    $key_d3ba = { 84 c8 [2] b6 ea [2] b0 df [2] 9e df [2] a1 c3 }

  condition:
    any of them
}