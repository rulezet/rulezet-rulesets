rule TTP_XOR_WriteProcessMemory_2f97 {
  strings:
    $key_2f97 = { 78 e5 [2] 4a c7 [2] 4c f2 [2] 62 f2 [2] 5d ee }

  condition:
    any of them
}