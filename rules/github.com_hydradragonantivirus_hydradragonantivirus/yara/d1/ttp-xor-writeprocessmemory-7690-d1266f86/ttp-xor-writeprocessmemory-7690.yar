rule TTP_XOR_WriteProcessMemory_7690 {
  strings:
    $key_7690 = { 21 e2 [2] 13 c0 [2] 15 f5 [2] 3b f5 [2] 04 e9 }

  condition:
    any of them
}