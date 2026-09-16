rule TTP_XOR_WriteProcessMemory_52c7 {
  strings:
    $key_52c7 = { 05 b5 [2] 37 97 [2] 31 a2 [2] 1f a2 [2] 20 be }

  condition:
    any of them
}