rule TTP_XOR_WriteProcessMemory_54d9 {
  strings:
    $key_54d9 = { 03 ab [2] 31 89 [2] 37 bc [2] 19 bc [2] 26 a0 }

  condition:
    any of them
}