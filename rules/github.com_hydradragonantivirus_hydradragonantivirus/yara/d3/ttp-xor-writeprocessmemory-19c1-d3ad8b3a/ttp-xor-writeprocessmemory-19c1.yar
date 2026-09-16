rule TTP_XOR_WriteProcessMemory_19c1 {
  strings:
    $key_19c1 = { 4e b3 [2] 7c 91 [2] 7a a4 [2] 54 a4 [2] 6b b8 }

  condition:
    any of them
}