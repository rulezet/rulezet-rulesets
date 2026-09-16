rule TTP_XOR_WriteProcessMemory_72c7 {
  strings:
    $key_72c7 = { 25 b5 [2] 17 97 [2] 11 a2 [2] 3f a2 [2] 00 be }

  condition:
    any of them
}