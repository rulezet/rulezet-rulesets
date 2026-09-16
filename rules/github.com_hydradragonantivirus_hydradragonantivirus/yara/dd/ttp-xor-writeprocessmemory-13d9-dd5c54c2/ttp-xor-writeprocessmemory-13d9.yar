rule TTP_XOR_WriteProcessMemory_13d9 {
  strings:
    $key_13d9 = { 44 ab [2] 76 89 [2] 70 bc [2] 5e bc [2] 61 a0 }

  condition:
    any of them
}