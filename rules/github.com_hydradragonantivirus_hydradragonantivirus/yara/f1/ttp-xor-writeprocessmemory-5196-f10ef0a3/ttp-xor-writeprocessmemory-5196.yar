rule TTP_XOR_WriteProcessMemory_5196 {
  strings:
    $key_5196 = { 06 e4 [2] 34 c6 [2] 32 f3 [2] 1c f3 [2] 23 ef }

  condition:
    any of them
}