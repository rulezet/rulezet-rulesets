rule TTP_XOR_WriteProcessMemory_f592 {
  strings:
    $key_f592 = { a2 e0 [2] 90 c2 [2] 96 f7 [2] b8 f7 [2] 87 eb }

  condition:
    any of them
}