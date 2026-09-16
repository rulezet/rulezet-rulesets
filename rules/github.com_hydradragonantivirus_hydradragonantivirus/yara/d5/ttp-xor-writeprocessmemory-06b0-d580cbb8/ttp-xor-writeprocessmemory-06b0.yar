rule TTP_XOR_WriteProcessMemory_06b0 {
  strings:
    $key_06b0 = { 51 c2 [2] 63 e0 [2] 65 d5 [2] 4b d5 [2] 74 c9 }

  condition:
    any of them
}