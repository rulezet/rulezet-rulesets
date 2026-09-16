rule TTP_XOR_WriteProcessMemory_27b6 {
  strings:
    $key_27b6 = { 70 c4 [2] 42 e6 [2] 44 d3 [2] 6a d3 [2] 55 cf }

  condition:
    any of them
}