rule TTP_XOR_WriteProcessMemory_d3e5 {
  strings:
    $key_d3e5 = { 84 97 [2] b6 b5 [2] b0 80 [2] 9e 80 [2] a1 9c }

  condition:
    any of them
}