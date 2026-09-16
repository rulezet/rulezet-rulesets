rule TTP_XOR_WriteProcessMemory_d652 {
  strings:
    $key_d652 = { 81 20 [2] b3 02 [2] b5 37 [2] 9b 37 [2] a4 2b }

  condition:
    any of them
}