rule TTP_XOR_WriteProcessMemory_09c1 {
  strings:
    $key_09c1 = { 5e b3 [2] 6c 91 [2] 6a a4 [2] 44 a4 [2] 7b b8 }

  condition:
    any of them
}