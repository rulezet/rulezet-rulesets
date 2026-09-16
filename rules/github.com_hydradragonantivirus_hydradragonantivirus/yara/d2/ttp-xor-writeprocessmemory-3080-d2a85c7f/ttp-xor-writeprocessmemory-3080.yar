rule TTP_XOR_WriteProcessMemory_3080 {
  strings:
    $key_3080 = { 67 f2 [2] 55 d0 [2] 53 e5 [2] 7d e5 [2] 42 f9 }

  condition:
    any of them
}