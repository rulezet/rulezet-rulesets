rule TTP_XOR_WriteProcessMemory_d6f3 {
  strings:
    $key_d6f3 = { 81 81 [2] b3 a3 [2] b5 96 [2] 9b 96 [2] a4 8a }

  condition:
    any of them
}