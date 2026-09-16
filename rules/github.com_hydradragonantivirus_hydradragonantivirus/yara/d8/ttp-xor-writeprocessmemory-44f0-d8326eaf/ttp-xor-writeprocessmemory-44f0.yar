rule TTP_XOR_WriteProcessMemory_44f0 {
  strings:
    $key_44f0 = { 13 82 [2] 21 a0 [2] 27 95 [2] 09 95 [2] 36 89 }

  condition:
    any of them
}