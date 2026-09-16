rule TTP_XOR_WriteProcessMemory_34ba {
  strings:
    $key_34ba = { 63 c8 [2] 51 ea [2] 57 df [2] 79 df [2] 46 c3 }

  condition:
    any of them
}