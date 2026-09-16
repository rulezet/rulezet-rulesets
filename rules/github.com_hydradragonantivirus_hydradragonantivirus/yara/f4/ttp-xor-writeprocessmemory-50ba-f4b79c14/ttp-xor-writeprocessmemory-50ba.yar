rule TTP_XOR_WriteProcessMemory_50ba {
  strings:
    $key_50ba = { 07 c8 [2] 35 ea [2] 33 df [2] 1d df [2] 22 c3 }

  condition:
    any of them
}