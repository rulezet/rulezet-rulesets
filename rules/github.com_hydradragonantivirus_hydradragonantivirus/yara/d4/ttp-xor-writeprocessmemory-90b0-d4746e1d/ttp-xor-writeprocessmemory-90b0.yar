rule TTP_XOR_WriteProcessMemory_90b0 {
  strings:
    $key_90b0 = { c7 c2 [2] f5 e0 [2] f3 d5 [2] dd d5 [2] e2 c9 }

  condition:
    any of them
}