rule TTP_XOR_WriteProcessMemory_e4ba {
  strings:
    $key_e4ba = { b3 c8 [2] 81 ea [2] 87 df [2] a9 df [2] 96 c3 }

  condition:
    any of them
}