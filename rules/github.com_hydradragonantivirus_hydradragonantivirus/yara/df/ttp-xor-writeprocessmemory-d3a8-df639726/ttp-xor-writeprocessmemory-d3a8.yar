rule TTP_XOR_WriteProcessMemory_d3a8 {
  strings:
    $key_d3a8 = { 84 da [2] b6 f8 [2] b0 cd [2] 9e cd [2] a1 d1 }

  condition:
    any of them
}