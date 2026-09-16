rule TTP_XOR_WriteProcessMemory_5197 {
  strings:
    $key_5197 = { 06 e5 [2] 34 c7 [2] 32 f2 [2] 1c f2 [2] 23 ee }

  condition:
    any of them
}