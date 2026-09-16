rule TTP_XOR_WriteProcessMemory_c7c7 {
  strings:
    $key_c7c7 = { 90 b5 [2] a2 97 [2] a4 a2 [2] 8a a2 [2] b5 be }

  condition:
    any of them
}