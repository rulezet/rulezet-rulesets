rule TTP_XOR_WriteProcessMemory_6f83 {
  strings:
    $key_6f83 = { 38 f1 [2] 0a d3 [2] 0c e6 [2] 22 e6 [2] 1d fa }

  condition:
    any of them
}