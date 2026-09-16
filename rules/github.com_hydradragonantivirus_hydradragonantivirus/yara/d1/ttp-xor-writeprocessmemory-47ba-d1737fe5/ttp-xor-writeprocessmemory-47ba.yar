rule TTP_XOR_WriteProcessMemory_47ba {
  strings:
    $key_47ba = { 10 c8 [2] 22 ea [2] 24 df [2] 0a df [2] 35 c3 }

  condition:
    any of them
}