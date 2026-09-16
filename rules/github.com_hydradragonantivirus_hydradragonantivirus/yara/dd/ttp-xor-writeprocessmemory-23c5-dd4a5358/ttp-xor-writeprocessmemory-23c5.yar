rule TTP_XOR_WriteProcessMemory_23c5 {
  strings:
    $key_23c5 = { 74 b7 [2] 46 95 [2] 40 a0 [2] 6e a0 [2] 51 bc }

  condition:
    any of them
}