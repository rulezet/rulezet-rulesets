rule TTP_XOR_WriteProcessMemory_74c7 {
  strings:
    $key_74c7 = { 23 b5 [2] 11 97 [2] 17 a2 [2] 39 a2 [2] 06 be }

  condition:
    any of them
}