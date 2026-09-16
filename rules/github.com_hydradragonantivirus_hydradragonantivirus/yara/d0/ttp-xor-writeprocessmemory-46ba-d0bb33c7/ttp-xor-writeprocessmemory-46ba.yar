rule TTP_XOR_WriteProcessMemory_46ba {
  strings:
    $key_46ba = { 11 c8 [2] 23 ea [2] 25 df [2] 0b df [2] 34 c3 }

  condition:
    any of them
}