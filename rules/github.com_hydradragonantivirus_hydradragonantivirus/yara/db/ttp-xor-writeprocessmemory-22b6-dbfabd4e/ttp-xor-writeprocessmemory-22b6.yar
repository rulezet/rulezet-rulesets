rule TTP_XOR_WriteProcessMemory_22b6 {
  strings:
    $key_22b6 = { 75 c4 [2] 47 e6 [2] 41 d3 [2] 6f d3 [2] 50 cf }

  condition:
    any of them
}