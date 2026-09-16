rule TTP_XOR_WriteProcessMemory_d122 {
  strings:
    $key_d122 = { 86 50 [2] b4 72 [2] b2 47 [2] 9c 47 [2] a3 5b }

  condition:
    any of them
}