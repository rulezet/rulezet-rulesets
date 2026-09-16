rule TTP_XOR_WriteProcessMemory_72d0 {
  strings:
    $key_72d0 = { 25 a2 [2] 17 80 [2] 11 b5 [2] 3f b5 [2] 00 a9 }

  condition:
    any of them
}