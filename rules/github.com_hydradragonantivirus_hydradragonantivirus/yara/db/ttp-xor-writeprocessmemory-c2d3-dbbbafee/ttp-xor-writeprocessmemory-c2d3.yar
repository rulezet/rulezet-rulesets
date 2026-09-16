rule TTP_XOR_WriteProcessMemory_c2d3 {
  strings:
    $key_c2d3 = { 95 a1 [2] a7 83 [2] a1 b6 [2] 8f b6 [2] b0 aa }

  condition:
    any of them
}