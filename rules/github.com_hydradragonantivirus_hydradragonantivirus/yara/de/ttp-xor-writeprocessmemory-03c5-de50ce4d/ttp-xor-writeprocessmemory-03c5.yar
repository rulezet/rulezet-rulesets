rule TTP_XOR_WriteProcessMemory_03c5 {
  strings:
    $key_03c5 = { 54 b7 [2] 66 95 [2] 60 a0 [2] 4e a0 [2] 71 bc }

  condition:
    any of them
}