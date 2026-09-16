rule TTP_XOR_WriteProcessMemory_54ba {
  strings:
    $key_54ba = { 03 c8 [2] 31 ea [2] 37 df [2] 19 df [2] 26 c3 }

  condition:
    any of them
}