rule TTP_XOR_WriteProcessMemory_2f83 {
  strings:
    $key_2f83 = { 78 f1 [2] 4a d3 [2] 4c e6 [2] 62 e6 [2] 5d fa }

  condition:
    any of them
}