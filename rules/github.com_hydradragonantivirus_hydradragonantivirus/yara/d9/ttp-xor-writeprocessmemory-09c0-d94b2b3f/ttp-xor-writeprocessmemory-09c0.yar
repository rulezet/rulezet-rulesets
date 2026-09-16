rule TTP_XOR_WriteProcessMemory_09c0 {
  strings:
    $key_09c0 = { 5e b2 [2] 6c 90 [2] 6a a5 [2] 44 a5 [2] 7b b9 }

  condition:
    any of them
}