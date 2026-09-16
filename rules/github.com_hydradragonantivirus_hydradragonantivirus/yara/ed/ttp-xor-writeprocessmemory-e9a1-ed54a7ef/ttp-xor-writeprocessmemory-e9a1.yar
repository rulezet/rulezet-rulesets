rule TTP_XOR_WriteProcessMemory_e9a1 {
  strings:
    $key_e9a1 = { be d3 [2] 8c f1 [2] 8a c4 [2] a4 c4 [2] 9b d8 }

  condition:
    any of them
}