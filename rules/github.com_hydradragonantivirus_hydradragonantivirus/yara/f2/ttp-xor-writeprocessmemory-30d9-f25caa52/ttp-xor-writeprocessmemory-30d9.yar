rule TTP_XOR_WriteProcessMemory_30d9 {
  strings:
    $key_30d9 = { 67 ab [2] 55 89 [2] 53 bc [2] 7d bc [2] 42 a0 }

  condition:
    any of them
}