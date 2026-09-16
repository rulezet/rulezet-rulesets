rule TTP_XOR_WriteProcessMemory_51c1 {
  strings:
    $key_51c1 = { 06 b3 [2] 34 91 [2] 32 a4 [2] 1c a4 [2] 23 b8 }

  condition:
    any of them
}