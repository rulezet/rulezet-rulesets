rule TTP_XOR_WriteProcessMemory_18c0 {
  strings:
    $key_18c0 = { 4f b2 [2] 7d 90 [2] 7b a5 [2] 55 a5 [2] 6a b9 }

  condition:
    any of them
}