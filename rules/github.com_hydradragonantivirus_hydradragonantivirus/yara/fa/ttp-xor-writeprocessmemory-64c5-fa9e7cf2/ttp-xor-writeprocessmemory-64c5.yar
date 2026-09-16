rule TTP_XOR_WriteProcessMemory_64c5 {
  strings:
    $key_64c5 = { 33 b7 [2] 01 95 [2] 07 a0 [2] 29 a0 [2] 16 bc }

  condition:
    any of them
}