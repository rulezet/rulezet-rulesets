rule TTP_XOR_WriteProcessMemory_d6c7 {
  strings:
    $key_d6c7 = { 81 b5 [2] b3 97 [2] b5 a2 [2] 9b a2 [2] a4 be }

  condition:
    any of them
}