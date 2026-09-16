rule TTP_XOR_WriteProcessMemory_5092 {
  strings:
    $key_5092 = { 07 e0 [2] 35 c2 [2] 33 f7 [2] 1d f7 [2] 22 eb }

  condition:
    any of them
}