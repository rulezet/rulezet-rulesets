rule TTP_XOR_WriteProcessMemory_55b1 {
  strings:
    $key_55b1 = { 02 c3 [2] 30 e1 [2] 36 d4 [2] 18 d4 [2] 27 c8 }

  condition:
    any of them
}