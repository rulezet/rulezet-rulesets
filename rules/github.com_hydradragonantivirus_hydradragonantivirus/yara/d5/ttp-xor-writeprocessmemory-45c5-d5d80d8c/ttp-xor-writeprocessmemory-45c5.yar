rule TTP_XOR_WriteProcessMemory_45c5 {
  strings:
    $key_45c5 = { 12 b7 [2] 20 95 [2] 26 a0 [2] 08 a0 [2] 37 bc }

  condition:
    any of them
}