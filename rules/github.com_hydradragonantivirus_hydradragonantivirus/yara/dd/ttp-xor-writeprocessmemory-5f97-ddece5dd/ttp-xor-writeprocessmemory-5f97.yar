rule TTP_XOR_WriteProcessMemory_5f97 {
  strings:
    $key_5f97 = { 08 e5 [2] 3a c7 [2] 3c f2 [2] 12 f2 [2] 2d ee }

  condition:
    any of them
}