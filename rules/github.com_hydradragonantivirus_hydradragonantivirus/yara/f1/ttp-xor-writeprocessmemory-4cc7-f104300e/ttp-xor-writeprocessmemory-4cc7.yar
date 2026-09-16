rule TTP_XOR_WriteProcessMemory_4cc7 {
  strings:
    $key_4cc7 = { 1b b5 [2] 29 97 [2] 2f a2 [2] 01 a2 [2] 3e be }

  condition:
    any of them
}