rule TTP_XOR_WriteProcessMemory_4797 {
  strings:
    $key_4797 = { 10 e5 [2] 22 c7 [2] 24 f2 [2] 0a f2 [2] 35 ee }

  condition:
    any of them
}