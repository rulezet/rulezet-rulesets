rule TTP_XOR_WriteProcessMemory_90b1 {
  strings:
    $key_90b1 = { c7 c3 [2] f5 e1 [2] f3 d4 [2] dd d4 [2] e2 c8 }

  condition:
    any of them
}