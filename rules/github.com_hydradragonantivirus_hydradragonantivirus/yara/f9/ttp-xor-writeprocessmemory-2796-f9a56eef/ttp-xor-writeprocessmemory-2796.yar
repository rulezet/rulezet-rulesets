rule TTP_XOR_WriteProcessMemory_2796 {
  strings:
    $key_2796 = { 70 e4 [2] 42 c6 [2] 44 f3 [2] 6a f3 [2] 55 ef }

  condition:
    any of them
}