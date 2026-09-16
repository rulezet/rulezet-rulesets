rule TTP_XOR_WriteProcessMemory_4297 {
  strings:
    $key_4297 = { 15 e5 [2] 27 c7 [2] 21 f2 [2] 0f f2 [2] 30 ee }

  condition:
    any of them
}