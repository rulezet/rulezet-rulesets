rule TTP_XOR_WriteProcessMemory_e0c5 {
  strings:
    $key_e0c5 = { b7 b7 [2] 85 95 [2] 83 a0 [2] ad a0 [2] 92 bc }

  condition:
    any of them
}