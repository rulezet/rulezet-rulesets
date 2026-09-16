rule TTP_XOR_WriteProcessMemory_f792 {
  strings:
    $key_f792 = { a0 e0 [2] 92 c2 [2] 94 f7 [2] ba f7 [2] 85 eb }

  condition:
    any of them
}