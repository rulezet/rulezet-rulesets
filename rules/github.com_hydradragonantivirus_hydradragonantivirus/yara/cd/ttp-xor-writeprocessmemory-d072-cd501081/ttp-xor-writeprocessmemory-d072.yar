rule TTP_XOR_WriteProcessMemory_d072 {
  strings:
    $key_d072 = { 87 00 [2] b5 22 [2] b3 17 [2] 9d 17 [2] a2 0b }

  condition:
    any of them
}