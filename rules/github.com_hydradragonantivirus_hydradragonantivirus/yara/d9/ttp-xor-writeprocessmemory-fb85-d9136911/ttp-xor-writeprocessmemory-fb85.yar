rule TTP_XOR_WriteProcessMemory_fb85 {
  strings:
    $key_fb85 = { ac f7 [2] 9e d5 [2] 98 e0 [2] b6 e0 [2] 89 fc }

  condition:
    any of them
}