rule TTP_XOR_WriteProcessMemory_51e0 {
  strings:
    $key_51e0 = { 06 92 [2] 34 b0 [2] 32 85 [2] 1c 85 [2] 23 99 }

  condition:
    any of them
}