rule TTP_XOR_WriteProcessMemory_41b6 {
  strings:
    $key_41b6 = { 16 c4 [2] 24 e6 [2] 22 d3 [2] 0c d3 [2] 33 cf }

  condition:
    any of them
}