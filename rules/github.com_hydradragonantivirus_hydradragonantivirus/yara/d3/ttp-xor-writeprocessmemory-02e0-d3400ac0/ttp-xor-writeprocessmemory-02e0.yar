rule TTP_XOR_WriteProcessMemory_02e0 {
  strings:
    $key_02e0 = { 55 92 [2] 67 b0 [2] 61 85 [2] 4f 85 [2] 70 99 }

  condition:
    any of them
}