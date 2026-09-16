rule TTP_XOR_WriteProcessMemory_43d9 {
  strings:
    $key_43d9 = { 14 ab [2] 26 89 [2] 20 bc [2] 0e bc [2] 31 a0 }

  condition:
    any of them
}