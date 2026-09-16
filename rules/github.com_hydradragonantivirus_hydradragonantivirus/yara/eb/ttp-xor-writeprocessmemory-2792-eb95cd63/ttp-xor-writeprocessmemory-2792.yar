rule TTP_XOR_WriteProcessMemory_2792 {
  strings:
    $key_2792 = { 70 e0 [2] 42 c2 [2] 44 f7 [2] 6a f7 [2] 55 eb }

  condition:
    any of them
}