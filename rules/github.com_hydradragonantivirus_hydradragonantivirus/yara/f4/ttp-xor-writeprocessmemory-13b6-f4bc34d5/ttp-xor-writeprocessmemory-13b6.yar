rule TTP_XOR_WriteProcessMemory_13b6 {
  strings:
    $key_13b6 = { 44 c4 [2] 76 e6 [2] 70 d3 [2] 5e d3 [2] 61 cf }

  condition:
    any of them
}