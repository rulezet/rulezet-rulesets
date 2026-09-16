rule TTP_XOR_WriteProcessMemory_d3f2 {
  strings:
    $key_d3f2 = { 84 80 [2] b6 a2 [2] b0 97 [2] 9e 97 [2] a1 8b }

  condition:
    any of them
}