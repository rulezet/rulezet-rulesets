rule TTP_XOR_WriteProcessMemory_3cb0 {
  strings:
    $key_3cb0 = { 6b c2 [2] 59 e0 [2] 5f d5 [2] 71 d5 [2] 4e c9 }

  condition:
    any of them
}