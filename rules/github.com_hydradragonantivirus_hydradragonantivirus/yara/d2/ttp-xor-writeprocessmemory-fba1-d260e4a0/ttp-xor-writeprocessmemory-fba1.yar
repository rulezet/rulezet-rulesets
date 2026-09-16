rule TTP_XOR_WriteProcessMemory_fba1 {
  strings:
    $key_fba1 = { ac d3 [2] 9e f1 [2] 98 c4 [2] b6 c4 [2] 89 d8 }

  condition:
    any of them
}