rule TTP_XOR_WriteProcessMemory_53ba {
  strings:
    $key_53ba = { 04 c8 [2] 36 ea [2] 30 df [2] 1e df [2] 21 c3 }

  condition:
    any of them
}