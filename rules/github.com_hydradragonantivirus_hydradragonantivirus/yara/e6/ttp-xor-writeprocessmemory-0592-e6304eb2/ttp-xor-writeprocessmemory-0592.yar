rule TTP_XOR_WriteProcessMemory_0592 {
  strings:
    $key_0592 = { 52 e0 [2] 60 c2 [2] 66 f7 [2] 48 f7 [2] 77 eb }

  condition:
    any of them
}