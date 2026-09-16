rule TTP_XOR_WriteProcessMemory_c1e4 {
  strings:
    $key_c1e4 = { 96 96 [2] a4 b4 [2] a2 81 [2] 8c 81 [2] b3 9d }

  condition:
    any of them
}