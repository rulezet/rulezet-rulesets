rule TTP_XOR_WriteProcessMemory_72f2 {
  strings:
    $key_72f2 = { 25 80 [2] 17 a2 [2] 11 97 [2] 3f 97 [2] 00 8b }

  condition:
    any of them
}