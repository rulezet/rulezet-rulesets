rule TTP_XOR_WriteProcessMemory_ff83 {
  strings:
    $key_ff83 = { a8 f1 [2] 9a d3 [2] 9c e6 [2] b2 e6 [2] 8d fa }

  condition:
    any of them
}