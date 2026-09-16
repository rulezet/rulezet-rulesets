rule TTP_XOR_WriteProcessMemory_1df0 {
  strings:
    $key_1df0 = { 4a 82 [2] 78 a0 [2] 7e 95 [2] 50 95 [2] 6f 89 }

  condition:
    any of them
}