rule TTP_XOR_WriteProcessMemory_d0b6 {
  strings:
    $key_d0b6 = { 87 c4 [2] b5 e6 [2] b3 d3 [2] 9d d3 [2] a2 cf }

  condition:
    any of them
}