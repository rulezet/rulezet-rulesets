rule TTP_XOR_WriteProcessMemory_e8a4 {
  strings:
    $key_e8a4 = { bf d6 [2] 8d f4 [2] 8b c1 [2] a5 c1 [2] 9a dd }

  condition:
    any of them
}