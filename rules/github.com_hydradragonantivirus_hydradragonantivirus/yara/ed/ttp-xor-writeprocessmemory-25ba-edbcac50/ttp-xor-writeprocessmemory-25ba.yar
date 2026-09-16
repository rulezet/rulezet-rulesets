rule TTP_XOR_WriteProcessMemory_25ba {
  strings:
    $key_25ba = { 72 c8 [2] 40 ea [2] 46 df [2] 68 df [2] 57 c3 }

  condition:
    any of them
}