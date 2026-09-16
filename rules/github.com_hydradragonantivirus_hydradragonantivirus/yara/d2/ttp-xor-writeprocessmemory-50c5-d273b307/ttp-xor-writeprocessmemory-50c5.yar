rule TTP_XOR_WriteProcessMemory_50c5 {
  strings:
    $key_50c5 = { 07 b7 [2] 35 95 [2] 33 a0 [2] 1d a0 [2] 22 bc }

  condition:
    any of them
}