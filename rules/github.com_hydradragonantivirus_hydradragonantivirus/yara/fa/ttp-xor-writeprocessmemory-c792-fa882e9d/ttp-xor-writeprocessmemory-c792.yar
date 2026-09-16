rule TTP_XOR_WriteProcessMemory_c792 {
  strings:
    $key_c792 = { 90 e0 [2] a2 c2 [2] a4 f7 [2] 8a f7 [2] b5 eb }

  condition:
    any of them
}