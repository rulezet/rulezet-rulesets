rule TTP_XOR_WriteProcessMemory_d3c8 {
  strings:
    $key_d3c8 = { 84 ba [2] b6 98 [2] b0 ad [2] 9e ad [2] a1 b1 }

  condition:
    any of them
}