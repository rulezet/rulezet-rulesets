rule TTP_XOR_WriteProcessMemory_00b0 {
  strings:
    $key_00b0 = { 57 c2 [2] 65 e0 [2] 63 d5 [2] 4d d5 [2] 72 c9 }

  condition:
    any of them
}