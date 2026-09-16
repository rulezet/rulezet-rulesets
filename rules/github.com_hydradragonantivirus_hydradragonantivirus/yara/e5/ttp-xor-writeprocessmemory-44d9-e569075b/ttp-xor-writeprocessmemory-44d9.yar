rule TTP_XOR_WriteProcessMemory_44d9 {
  strings:
    $key_44d9 = { 13 ab [2] 21 89 [2] 27 bc [2] 09 bc [2] 36 a0 }

  condition:
    any of them
}