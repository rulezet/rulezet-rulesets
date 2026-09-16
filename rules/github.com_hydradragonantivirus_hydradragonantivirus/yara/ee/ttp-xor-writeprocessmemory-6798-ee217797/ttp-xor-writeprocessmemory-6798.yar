rule TTP_XOR_WriteProcessMemory_6798 {
  strings:
    $key_6798 = { 30 ea [2] 02 c8 [2] 04 fd [2] 2a fd [2] 15 e1 }

  condition:
    any of them
}