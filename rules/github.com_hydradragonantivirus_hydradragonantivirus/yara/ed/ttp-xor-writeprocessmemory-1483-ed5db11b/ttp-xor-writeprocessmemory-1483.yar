rule TTP_XOR_WriteProcessMemory_1483 {
  strings:
    $key_1483 = { 43 f1 [2] 71 d3 [2] 77 e6 [2] 59 e6 [2] 66 fa }

  condition:
    any of them
}