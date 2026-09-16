rule TTP_XOR_WriteProcessMemory_52b0 {
  strings:
    $key_52b0 = { 05 c2 [2] 37 e0 [2] 31 d5 [2] 1f d5 [2] 20 c9 }

  condition:
    any of them
}