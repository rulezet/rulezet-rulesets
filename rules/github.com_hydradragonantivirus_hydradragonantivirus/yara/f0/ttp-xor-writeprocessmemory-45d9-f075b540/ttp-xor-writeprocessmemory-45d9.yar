rule TTP_XOR_WriteProcessMemory_45d9 {
  strings:
    $key_45d9 = { 12 ab [2] 20 89 [2] 26 bc [2] 08 bc [2] 37 a0 }

  condition:
    any of them
}