rule TTP_XOR_WriteProcessMemory_3cd4 {
  strings:
    $key_3cd4 = { 6b a6 [2] 59 84 [2] 5f b1 [2] 71 b1 [2] 4e ad }

  condition:
    any of them
}