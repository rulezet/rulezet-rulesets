rule TTP_XOR_WriteProcessMemory_05a1 {
  strings:
    $key_05a1 = { 52 d3 [2] 60 f1 [2] 66 c4 [2] 48 c4 [2] 77 d8 }

  condition:
    any of them
}