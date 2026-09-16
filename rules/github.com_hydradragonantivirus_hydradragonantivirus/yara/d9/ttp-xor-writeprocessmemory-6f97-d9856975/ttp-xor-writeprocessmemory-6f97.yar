rule TTP_XOR_WriteProcessMemory_6f97 {
  strings:
    $key_6f97 = { 38 e5 [2] 0a c7 [2] 0c f2 [2] 22 f2 [2] 1d ee }

  condition:
    any of them
}