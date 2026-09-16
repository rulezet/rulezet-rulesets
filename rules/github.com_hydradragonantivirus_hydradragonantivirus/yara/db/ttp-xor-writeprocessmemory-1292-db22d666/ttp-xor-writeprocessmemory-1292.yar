rule TTP_XOR_WriteProcessMemory_1292 {
  strings:
    $key_1292 = { 45 e0 [2] 77 c2 [2] 71 f7 [2] 5f f7 [2] 60 eb }

  condition:
    any of them
}