rule TTP_XOR_WriteProcessMemory_e5ba {
  strings:
    $key_e5ba = { b2 c8 [2] 80 ea [2] 86 df [2] a8 df [2] 97 c3 }

  condition:
    any of them
}