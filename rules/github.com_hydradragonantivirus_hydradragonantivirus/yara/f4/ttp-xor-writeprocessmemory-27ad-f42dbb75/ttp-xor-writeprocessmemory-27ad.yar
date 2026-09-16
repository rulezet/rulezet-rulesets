rule TTP_XOR_WriteProcessMemory_27ad {
  strings:
    $key_27ad = { 70 df [2] 42 fd [2] 44 c8 [2] 6a c8 [2] 55 d4 }

  condition:
    any of them
}