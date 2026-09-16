rule TTP_XOR_WriteProcessMemory_d345 {
  strings:
    $key_d345 = { 84 37 [2] b6 15 [2] b0 20 [2] 9e 20 [2] a1 3c }

  condition:
    any of them
}