rule TTP_XOR_WriteProcessMemory_d2b6 {
  strings:
    $key_d2b6 = { 85 c4 [2] b7 e6 [2] b1 d3 [2] 9f d3 [2] a0 cf }

  condition:
    any of them
}