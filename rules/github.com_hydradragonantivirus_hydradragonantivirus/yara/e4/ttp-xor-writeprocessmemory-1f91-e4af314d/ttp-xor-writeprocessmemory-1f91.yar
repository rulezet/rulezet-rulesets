rule TTP_XOR_WriteProcessMemory_1f91 {
  strings:
    $key_1f91 = { 48 e3 [2] 7a c1 [2] 7c f4 [2] 52 f4 [2] 6d e8 }

  condition:
    any of them
}