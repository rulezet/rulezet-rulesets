rule TTP_XOR_WriteProcessMemory_36b0 {
  strings:
    $key_36b0 = { 61 c2 [2] 53 e0 [2] 55 d5 [2] 7b d5 [2] 44 c9 }

  condition:
    any of them
}