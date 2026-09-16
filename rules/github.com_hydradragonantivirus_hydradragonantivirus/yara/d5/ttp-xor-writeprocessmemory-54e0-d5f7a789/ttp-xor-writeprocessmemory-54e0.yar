rule TTP_XOR_WriteProcessMemory_54e0 {
  strings:
    $key_54e0 = { 03 92 [2] 31 b0 [2] 37 85 [2] 19 85 [2] 26 99 }

  condition:
    any of them
}