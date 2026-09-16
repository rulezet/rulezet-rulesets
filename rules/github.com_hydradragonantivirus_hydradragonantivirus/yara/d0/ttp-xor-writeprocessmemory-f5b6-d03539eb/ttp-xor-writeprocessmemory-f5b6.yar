rule TTP_XOR_WriteProcessMemory_f5b6 {
  strings:
    $key_f5b6 = { a2 c4 [2] 90 e6 [2] 96 d3 [2] b8 d3 [2] 87 cf }

  condition:
    any of them
}