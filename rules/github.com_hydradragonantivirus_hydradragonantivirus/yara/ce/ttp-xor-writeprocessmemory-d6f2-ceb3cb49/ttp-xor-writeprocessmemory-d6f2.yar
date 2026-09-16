rule TTP_XOR_WriteProcessMemory_d6f2 {
  strings:
    $key_d6f2 = { 81 80 [2] b3 a2 [2] b5 97 [2] 9b 97 [2] a4 8b }

  condition:
    any of them
}