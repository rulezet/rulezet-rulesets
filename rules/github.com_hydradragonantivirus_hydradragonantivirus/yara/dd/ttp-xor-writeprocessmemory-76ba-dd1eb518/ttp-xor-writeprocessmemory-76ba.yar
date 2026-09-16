rule TTP_XOR_WriteProcessMemory_76ba {
  strings:
    $key_76ba = { 21 c8 [2] 13 ea [2] 15 df [2] 3b df [2] 04 c3 }

  condition:
    any of them
}