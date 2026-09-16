rule TTP_XOR_WriteProcessMemory_d172 {
  strings:
    $key_d172 = { 86 00 [2] b4 22 [2] b2 17 [2] 9c 17 [2] a3 0b }

  condition:
    any of them
}