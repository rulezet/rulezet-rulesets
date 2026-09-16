rule TTP_XOR_WriteProcessMemory_1392 {
  strings:
    $key_1392 = { 44 e0 [2] 76 c2 [2] 70 f7 [2] 5e f7 [2] 61 eb }

  condition:
    any of them
}