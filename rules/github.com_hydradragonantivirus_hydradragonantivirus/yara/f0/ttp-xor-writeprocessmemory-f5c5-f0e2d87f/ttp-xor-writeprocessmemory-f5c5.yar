rule TTP_XOR_WriteProcessMemory_f5c5 {
  strings:
    $key_f5c5 = { a2 b7 [2] 90 95 [2] 96 a0 [2] b8 a0 [2] 87 bc }

  condition:
    any of them
}