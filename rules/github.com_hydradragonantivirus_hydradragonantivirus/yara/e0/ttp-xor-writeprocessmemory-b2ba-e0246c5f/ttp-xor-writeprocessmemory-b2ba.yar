rule TTP_XOR_WriteProcessMemory_b2ba {
  strings:
    $key_b2ba = { e5 c8 [2] d7 ea [2] d1 df [2] ff df [2] c0 c3 }

  condition:
    any of them
}