rule TTP_XOR_WriteProcessMemory_68c0 {
  strings:
    $key_68c0 = { 3f b2 [2] 0d 90 [2] 0b a5 [2] 25 a5 [2] 1a b9 }

  condition:
    any of them
}