rule TTP_XOR_WriteProcessMemory_2092 {
  strings:
    $key_2092 = { 77 e0 [2] 45 c2 [2] 43 f7 [2] 6d f7 [2] 52 eb }

  condition:
    any of them
}