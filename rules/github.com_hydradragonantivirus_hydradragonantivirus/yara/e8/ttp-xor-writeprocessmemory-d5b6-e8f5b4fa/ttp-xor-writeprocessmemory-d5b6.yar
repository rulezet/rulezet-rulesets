rule TTP_XOR_WriteProcessMemory_d5b6 {
  strings:
    $key_d5b6 = { 82 c4 [2] b0 e6 [2] b6 d3 [2] 98 d3 [2] a7 cf }

  condition:
    any of them
}