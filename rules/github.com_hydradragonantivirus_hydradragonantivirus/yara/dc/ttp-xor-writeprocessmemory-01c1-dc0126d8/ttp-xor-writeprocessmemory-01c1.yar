rule TTP_XOR_WriteProcessMemory_01c1 {
  strings:
    $key_01c1 = { 56 b3 [2] 64 91 [2] 62 a4 [2] 4c a4 [2] 73 b8 }

  condition:
    any of them
}