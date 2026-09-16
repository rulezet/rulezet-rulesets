rule TTP_XOR_WriteProcessMemory_64e0 {
  strings:
    $key_64e0 = { 33 92 [2] 01 b0 [2] 07 85 [2] 29 85 [2] 16 99 }

  condition:
    any of them
}