rule TTP_XOR_WriteProcessMemory_11b6 {
  strings:
    $key_11b6 = { 46 c4 [2] 74 e6 [2] 72 d3 [2] 5c d3 [2] 63 cf }

  condition:
    any of them
}