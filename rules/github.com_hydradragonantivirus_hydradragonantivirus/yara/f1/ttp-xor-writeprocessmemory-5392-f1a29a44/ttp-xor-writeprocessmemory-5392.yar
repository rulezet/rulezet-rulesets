rule TTP_XOR_WriteProcessMemory_5392 {
  strings:
    $key_5392 = { 04 e0 [2] 36 c2 [2] 30 f7 [2] 1e f7 [2] 21 eb }

  condition:
    any of them
}