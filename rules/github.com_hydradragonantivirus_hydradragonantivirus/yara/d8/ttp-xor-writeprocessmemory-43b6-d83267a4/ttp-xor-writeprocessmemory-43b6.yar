rule TTP_XOR_WriteProcessMemory_43b6 {
  strings:
    $key_43b6 = { 14 c4 [2] 26 e6 [2] 20 d3 [2] 0e d3 [2] 31 cf }

  condition:
    any of them
}