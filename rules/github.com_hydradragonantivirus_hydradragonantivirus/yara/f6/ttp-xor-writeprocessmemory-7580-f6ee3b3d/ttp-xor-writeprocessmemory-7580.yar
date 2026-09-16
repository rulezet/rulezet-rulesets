rule TTP_XOR_WriteProcessMemory_7580 {
  strings:
    $key_7580 = { 22 f2 [2] 10 d0 [2] 16 e5 [2] 38 e5 [2] 07 f9 }

  condition:
    any of them
}