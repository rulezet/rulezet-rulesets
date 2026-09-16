rule TTP_XOR_WriteProcessMemory_75e0 {
  strings:
    $key_75e0 = { 22 92 [2] 10 b0 [2] 16 85 [2] 38 85 [2] 07 99 }

  condition:
    any of them
}