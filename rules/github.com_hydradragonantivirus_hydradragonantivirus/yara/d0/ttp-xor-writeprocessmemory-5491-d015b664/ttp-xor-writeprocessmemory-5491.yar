rule TTP_XOR_WriteProcessMemory_5491 {
  strings:
    $key_5491 = { 03 e3 [2] 31 c1 [2] 37 f4 [2] 19 f4 [2] 26 e8 }

  condition:
    any of them
}