rule TTP_XOR_WriteProcessMemory_7dc1 {
  strings:
    $key_7dc1 = { 2a b3 [2] 18 91 [2] 1e a4 [2] 30 a4 [2] 0f b8 }

  condition:
    any of them
}