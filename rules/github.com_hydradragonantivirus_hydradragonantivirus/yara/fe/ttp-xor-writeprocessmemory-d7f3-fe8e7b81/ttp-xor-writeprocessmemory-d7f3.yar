rule TTP_XOR_WriteProcessMemory_d7f3 {
  strings:
    $key_d7f3 = { 80 81 [2] b2 a3 [2] b4 96 [2] 9a 96 [2] a5 8a }

  condition:
    any of them
}