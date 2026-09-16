rule TTP_XOR_WriteProcessMemory_64d9 {
  strings:
    $key_64d9 = { 33 ab [2] 01 89 [2] 07 bc [2] 29 bc [2] 16 a0 }

  condition:
    any of them
}