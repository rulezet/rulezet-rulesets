rule TTP_XOR_WriteProcessMemory_15d9 {
  strings:
    $key_15d9 = { 42 ab [2] 70 89 [2] 76 bc [2] 58 bc [2] 67 a0 }

  condition:
    any of them
}