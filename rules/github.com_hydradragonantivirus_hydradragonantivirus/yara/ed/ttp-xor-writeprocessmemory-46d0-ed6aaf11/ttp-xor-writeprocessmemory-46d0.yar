rule TTP_XOR_WriteProcessMemory_46d0 {
  strings:
    $key_46d0 = { 11 a2 [2] 23 80 [2] 25 b5 [2] 0b b5 [2] 34 a9 }

  condition:
    any of them
}