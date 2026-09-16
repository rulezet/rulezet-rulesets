rule TTP_XOR_WriteProcessMemory_78ba {
  strings:
    $key_78ba = { 2f c8 [2] 1d ea [2] 1b df [2] 35 df [2] 0a c3 }

  condition:
    any of them
}