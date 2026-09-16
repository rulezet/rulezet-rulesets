rule TTP_XOR_WriteProcessMemory_4392 {
  strings:
    $key_4392 = { 14 e0 [2] 26 c2 [2] 20 f7 [2] 0e f7 [2] 31 eb }

  condition:
    any of them
}