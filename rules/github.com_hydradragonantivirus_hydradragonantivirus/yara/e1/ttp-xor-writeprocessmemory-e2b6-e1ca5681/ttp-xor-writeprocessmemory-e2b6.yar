rule TTP_XOR_WriteProcessMemory_e2b6 {
  strings:
    $key_e2b6 = { b5 c4 [2] 87 e6 [2] 81 d3 [2] af d3 [2] 90 cf }

  condition:
    any of them
}