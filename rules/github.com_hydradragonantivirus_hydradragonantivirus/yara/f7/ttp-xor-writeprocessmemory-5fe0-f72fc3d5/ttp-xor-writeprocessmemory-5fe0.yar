rule TTP_XOR_WriteProcessMemory_5fe0 {
  strings:
    $key_5fe0 = { 08 92 [2] 3a b0 [2] 3c 85 [2] 12 85 [2] 2d 99 }

  condition:
    any of them
}