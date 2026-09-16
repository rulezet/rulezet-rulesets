rule TTP_XOR_WriteProcessMemory_a3ba {
  strings:
    $key_a3ba = { f4 c8 [2] c6 ea [2] c0 df [2] ee df [2] d1 c3 }

  condition:
    any of them
}