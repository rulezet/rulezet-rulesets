rule TTP_XOR_WriteProcessMemory_16b0 {
  strings:
    $key_16b0 = { 41 c2 [2] 73 e0 [2] 75 d5 [2] 5b d5 [2] 64 c9 }

  condition:
    any of them
}