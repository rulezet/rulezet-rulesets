rule TTP_XOR_WriteProcessMemory_c4c7 {
  strings:
    $key_c4c7 = { 93 b5 [2] a1 97 [2] a7 a2 [2] 89 a2 [2] b6 be }

  condition:
    any of them
}