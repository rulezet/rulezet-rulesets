rule TTP_XOR_WriteProcessMemory_f5d9 {
  strings:
    $key_f5d9 = { a2 ab [2] 90 89 [2] 96 bc [2] b8 bc [2] 87 a0 }

  condition:
    any of them
}