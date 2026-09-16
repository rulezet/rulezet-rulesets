rule TTP_XOR_WriteProcessMemory_4583 {
  strings:
    $key_4583 = { 12 f1 [2] 20 d3 [2] 26 e6 [2] 08 e6 [2] 37 fa }

  condition:
    any of them
}