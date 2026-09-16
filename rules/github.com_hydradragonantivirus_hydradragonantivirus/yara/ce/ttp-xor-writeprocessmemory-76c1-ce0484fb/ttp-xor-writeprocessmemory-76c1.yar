rule TTP_XOR_WriteProcessMemory_76c1 {
  strings:
    $key_76c1 = { 21 b3 [2] 13 91 [2] 15 a4 [2] 3b a4 [2] 04 b8 }

  condition:
    any of them
}