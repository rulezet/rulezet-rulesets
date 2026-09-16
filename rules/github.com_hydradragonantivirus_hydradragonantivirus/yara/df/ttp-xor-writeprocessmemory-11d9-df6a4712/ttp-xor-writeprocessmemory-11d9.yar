rule TTP_XOR_WriteProcessMemory_11d9 {
  strings:
    $key_11d9 = { 46 ab [2] 74 89 [2] 72 bc [2] 5c bc [2] 63 a0 }

  condition:
    any of them
}