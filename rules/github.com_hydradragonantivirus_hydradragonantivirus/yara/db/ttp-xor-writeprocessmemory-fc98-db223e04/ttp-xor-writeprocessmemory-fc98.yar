rule TTP_XOR_WriteProcessMemory_fc98 {
  strings:
    $key_fc98 = { ab ea [2] 99 c8 [2] 9f fd [2] b1 fd [2] 8e e1 }

  condition:
    any of them
}