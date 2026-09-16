rule TTP_XOR_WriteProcessMemory_d613 {
  strings:
    $key_d613 = { 81 61 [2] b3 43 [2] b5 76 [2] 9b 76 [2] a4 6a }

  condition:
    any of them
}