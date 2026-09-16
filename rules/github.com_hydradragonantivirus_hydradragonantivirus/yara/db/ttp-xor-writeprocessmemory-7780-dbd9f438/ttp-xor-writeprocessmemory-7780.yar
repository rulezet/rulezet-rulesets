rule TTP_XOR_WriteProcessMemory_7780 {
  strings:
    $key_7780 = { 20 f2 [2] 12 d0 [2] 14 e5 [2] 3a e5 [2] 05 f9 }

  condition:
    any of them
}