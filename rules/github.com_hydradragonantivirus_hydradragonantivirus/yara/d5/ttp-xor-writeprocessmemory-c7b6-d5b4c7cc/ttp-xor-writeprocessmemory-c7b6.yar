rule TTP_XOR_WriteProcessMemory_c7b6 {
  strings:
    $key_c7b6 = { 90 c4 [2] a2 e6 [2] a4 d3 [2] 8a d3 [2] b5 cf }

  condition:
    any of them
}