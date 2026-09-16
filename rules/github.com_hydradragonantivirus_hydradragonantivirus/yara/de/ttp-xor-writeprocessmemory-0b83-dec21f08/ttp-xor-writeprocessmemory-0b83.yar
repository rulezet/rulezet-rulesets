rule TTP_XOR_WriteProcessMemory_0b83 {
  strings:
    $key_0b83 = { 5c f1 [2] 6e d3 [2] 68 e6 [2] 46 e6 [2] 79 fa }

  condition:
    any of them
}