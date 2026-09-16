rule TTP_XOR_WriteProcessMemory_d643 {
  strings:
    $key_d643 = { 81 31 [2] b3 13 [2] b5 26 [2] 9b 26 [2] a4 3a }

  condition:
    any of them
}