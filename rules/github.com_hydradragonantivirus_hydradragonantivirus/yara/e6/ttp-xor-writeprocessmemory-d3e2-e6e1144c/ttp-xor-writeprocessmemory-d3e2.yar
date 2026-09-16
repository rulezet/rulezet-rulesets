rule TTP_XOR_WriteProcessMemory_d3e2 {
  strings:
    $key_d3e2 = { 84 90 [2] b6 b2 [2] b0 87 [2] 9e 87 [2] a1 9b }

  condition:
    any of them
}