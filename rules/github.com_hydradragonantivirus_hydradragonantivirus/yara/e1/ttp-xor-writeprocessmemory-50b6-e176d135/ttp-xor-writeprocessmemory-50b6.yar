rule TTP_XOR_WriteProcessMemory_50b6 {
  strings:
    $key_50b6 = { 07 c4 [2] 35 e6 [2] 33 d3 [2] 1d d3 [2] 22 cf }

  condition:
    any of them
}