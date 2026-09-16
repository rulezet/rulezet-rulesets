rule TTP_XOR_WriteProcessMemory_30ba {
  strings:
    $key_30ba = { 67 c8 [2] 55 ea [2] 53 df [2] 7d df [2] 42 c3 }

  condition:
    any of them
}