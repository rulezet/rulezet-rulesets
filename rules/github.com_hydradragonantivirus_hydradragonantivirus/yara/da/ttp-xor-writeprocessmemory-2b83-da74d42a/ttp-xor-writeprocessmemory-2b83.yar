rule TTP_XOR_WriteProcessMemory_2b83 {
  strings:
    $key_2b83 = { 7c f1 [2] 4e d3 [2] 48 e6 [2] 66 e6 [2] 59 fa }

  condition:
    any of them
}