rule TTP_XOR_WriteProcessMemory_4b83 {
  strings:
    $key_4b83 = { 1c f1 [2] 2e d3 [2] 28 e6 [2] 06 e6 [2] 39 fa }

  condition:
    any of them
}