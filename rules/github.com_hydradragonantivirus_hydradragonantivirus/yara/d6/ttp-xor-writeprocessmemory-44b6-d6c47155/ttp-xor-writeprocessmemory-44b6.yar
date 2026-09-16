rule TTP_XOR_WriteProcessMemory_44b6 {
  strings:
    $key_44b6 = { 13 c4 [2] 21 e6 [2] 27 d3 [2] 09 d3 [2] 36 cf }

  condition:
    any of them
}