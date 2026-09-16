rule TTP_XOR_WriteProcessMemory_26b1 {
  strings:
    $key_26b1 = { 71 c3 [2] 43 e1 [2] 45 d4 [2] 6b d4 [2] 54 c8 }

  condition:
    any of them
}