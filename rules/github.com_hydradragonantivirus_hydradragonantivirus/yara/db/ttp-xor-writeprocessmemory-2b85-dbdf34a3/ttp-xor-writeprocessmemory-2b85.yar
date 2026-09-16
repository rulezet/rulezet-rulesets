rule TTP_XOR_WriteProcessMemory_2b85 {
  strings:
    $key_2b85 = { 7c f7 [2] 4e d5 [2] 48 e0 [2] 66 e0 [2] 59 fc }

  condition:
    any of them
}