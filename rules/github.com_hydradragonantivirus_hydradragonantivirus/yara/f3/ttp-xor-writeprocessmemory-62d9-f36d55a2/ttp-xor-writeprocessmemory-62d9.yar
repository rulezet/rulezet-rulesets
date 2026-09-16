rule TTP_XOR_WriteProcessMemory_62d9 {
  strings:
    $key_62d9 = { 35 ab [2] 07 89 [2] 01 bc [2] 2f bc [2] 10 a0 }

  condition:
    any of them
}