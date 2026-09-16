rule TTP_XOR_WriteProcessMemory_1383 {
  strings:
    $key_1383 = { 44 f1 [2] 76 d3 [2] 70 e6 [2] 5e e6 [2] 61 fa }

  condition:
    any of them
}