rule TTP_XOR_WriteProcessMemory_22c7 {
  strings:
    $key_22c7 = { 75 b5 [2] 47 97 [2] 41 a2 [2] 6f a2 [2] 50 be }

  condition:
    any of them
}