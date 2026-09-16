rule TTP_XOR_WriteProcessMemory_d3d7 {
  strings:
    $key_d3d7 = { 84 a5 [2] b6 87 [2] b0 b2 [2] 9e b2 [2] a1 ae }

  condition:
    any of them
}