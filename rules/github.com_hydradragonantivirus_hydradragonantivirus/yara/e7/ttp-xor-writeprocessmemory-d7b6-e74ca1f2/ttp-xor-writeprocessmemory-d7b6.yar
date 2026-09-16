rule TTP_XOR_WriteProcessMemory_d7b6 {
  strings:
    $key_d7b6 = { 80 c4 [2] b2 e6 [2] b4 d3 [2] 9a d3 [2] a5 cf }

  condition:
    any of them
}