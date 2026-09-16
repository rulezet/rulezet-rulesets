rule TTP_XOR_WriteProcessMemory_d777 {
  strings:
    $key_d777 = { 80 05 [2] b2 27 [2] b4 12 [2] 9a 12 [2] a5 0e }

  condition:
    any of them
}