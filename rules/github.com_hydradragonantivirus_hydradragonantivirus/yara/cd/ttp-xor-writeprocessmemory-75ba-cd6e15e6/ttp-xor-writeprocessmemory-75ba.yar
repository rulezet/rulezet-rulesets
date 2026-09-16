rule TTP_XOR_WriteProcessMemory_75ba {
  strings:
    $key_75ba = { 22 c8 [2] 10 ea [2] 16 df [2] 38 df [2] 07 c3 }

  condition:
    any of them
}