rule TTP_XOR_WriteProcessMemory_4690 {
  strings:
    $key_4690 = { 11 e2 [2] 23 c0 [2] 25 f5 [2] 0b f5 [2] 34 e9 }

  condition:
    any of them
}