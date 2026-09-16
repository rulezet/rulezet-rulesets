rule TTP_XOR_WriteProcessMemory_7cc7 {
  strings:
    $key_7cc7 = { 2b b5 [2] 19 97 [2] 1f a2 [2] 31 a2 [2] 0e be }

  condition:
    any of them
}