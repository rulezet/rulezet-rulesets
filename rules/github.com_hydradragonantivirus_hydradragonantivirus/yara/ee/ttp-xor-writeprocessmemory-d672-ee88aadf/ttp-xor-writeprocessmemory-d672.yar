rule TTP_XOR_WriteProcessMemory_d672 {
  strings:
    $key_d672 = { 81 00 [2] b3 22 [2] b5 17 [2] 9b 17 [2] a4 0b }

  condition:
    any of them
}