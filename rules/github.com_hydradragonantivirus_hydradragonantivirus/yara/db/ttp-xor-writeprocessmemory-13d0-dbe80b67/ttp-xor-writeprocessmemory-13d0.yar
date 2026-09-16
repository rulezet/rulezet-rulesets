rule TTP_XOR_WriteProcessMemory_13d0 {
  strings:
    $key_13d0 = { 44 a2 [2] 76 80 [2] 70 b5 [2] 5e b5 [2] 61 a9 }

  condition:
    any of them
}