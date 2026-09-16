rule TTP_XOR_WriteProcessMemory_c4b6 {
  strings:
    $key_c4b6 = { 93 c4 [2] a1 e6 [2] a7 d3 [2] 89 d3 [2] b6 cf }

  condition:
    any of them
}