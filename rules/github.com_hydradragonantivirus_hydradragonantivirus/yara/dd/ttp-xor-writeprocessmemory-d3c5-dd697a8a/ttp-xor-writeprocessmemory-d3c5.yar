rule TTP_XOR_WriteProcessMemory_d3c5 {
  strings:
    $key_d3c5 = { 84 b7 [2] b6 95 [2] b0 a0 [2] 9e a0 [2] a1 bc }

  condition:
    any of them
}