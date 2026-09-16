rule TTP_XOR_WriteProcessMemory_08c1 {
  strings:
    $key_08c1 = { 5f b3 [2] 6d 91 [2] 6b a4 [2] 45 a4 [2] 7a b8 }

  condition:
    any of them
}