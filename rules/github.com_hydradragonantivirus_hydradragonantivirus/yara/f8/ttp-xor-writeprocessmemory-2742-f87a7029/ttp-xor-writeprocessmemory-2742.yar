rule TTP_XOR_WriteProcessMemory_2742 {
  strings:
    $key_2742 = { 70 30 [2] 42 12 [2] 44 27 [2] 6a 27 [2] 55 3b }

  condition:
    any of them
}