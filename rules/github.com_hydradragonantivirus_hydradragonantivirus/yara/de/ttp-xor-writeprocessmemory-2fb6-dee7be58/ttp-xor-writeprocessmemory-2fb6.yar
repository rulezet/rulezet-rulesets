rule TTP_XOR_WriteProcessMemory_2fb6 {
  strings:
    $key_2fb6 = { 78 c4 [2] 4a e6 [2] 4c d3 [2] 62 d3 [2] 5d cf }

  condition:
    any of them
}