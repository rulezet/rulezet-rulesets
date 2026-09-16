rule TTP_XOR_WriteProcessMemory_c3d3 {
  strings:
    $key_c3d3 = { 94 a1 [2] a6 83 [2] a0 b6 [2] 8e b6 [2] b1 aa }

  condition:
    any of them
}