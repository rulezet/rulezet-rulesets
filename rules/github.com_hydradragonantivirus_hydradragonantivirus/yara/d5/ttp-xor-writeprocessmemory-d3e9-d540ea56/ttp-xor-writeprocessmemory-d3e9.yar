rule TTP_XOR_WriteProcessMemory_d3e9 {
  strings:
    $key_d3e9 = { 84 9b [2] b6 b9 [2] b0 8c [2] 9e 8c [2] a1 90 }

  condition:
    any of them
}