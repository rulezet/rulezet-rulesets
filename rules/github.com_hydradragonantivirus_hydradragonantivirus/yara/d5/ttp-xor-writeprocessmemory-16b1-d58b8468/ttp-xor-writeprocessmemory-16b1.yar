rule TTP_XOR_WriteProcessMemory_16b1 {
  strings:
    $key_16b1 = { 41 c3 [2] 73 e1 [2] 75 d4 [2] 5b d4 [2] 64 c8 }

  condition:
    any of them
}