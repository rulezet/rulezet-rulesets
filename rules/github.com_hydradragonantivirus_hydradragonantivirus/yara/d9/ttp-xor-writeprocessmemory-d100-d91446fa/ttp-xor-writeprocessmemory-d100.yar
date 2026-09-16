rule TTP_XOR_WriteProcessMemory_d100 {
  strings:
    $key_d100 = { 86 72 [2] b4 50 [2] b2 65 [2] 9c 65 [2] a3 79 }

  condition:
    any of them
}