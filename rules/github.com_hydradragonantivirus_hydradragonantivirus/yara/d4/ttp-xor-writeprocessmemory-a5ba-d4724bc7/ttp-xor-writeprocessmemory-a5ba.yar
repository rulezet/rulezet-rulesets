rule TTP_XOR_WriteProcessMemory_a5ba {
  strings:
    $key_a5ba = { f2 c8 [2] c0 ea [2] c6 df [2] e8 df [2] d7 c3 }

  condition:
    any of them
}