rule TTP_XOR_WriteProcessMemory_41c1 {
  strings:
    $key_41c1 = { 16 b3 [2] 24 91 [2] 22 a4 [2] 0c a4 [2] 33 b8 }

  condition:
    any of them
}