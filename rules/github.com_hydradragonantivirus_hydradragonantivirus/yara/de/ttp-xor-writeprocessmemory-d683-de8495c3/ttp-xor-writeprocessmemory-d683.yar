rule TTP_XOR_WriteProcessMemory_d683 {
  strings:
    $key_d683 = { 81 f1 [2] b3 d3 [2] b5 e6 [2] 9b e6 [2] a4 fa }

  condition:
    any of them
}