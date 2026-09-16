rule TTP_XOR_WriteProcessMemory_f490 {
  strings:
    $key_f490 = { a3 e2 [2] 91 c0 [2] 97 f5 [2] b9 f5 [2] 86 e9 }

  condition:
    any of them
}