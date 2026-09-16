rule TTP_XOR_WriteProcessMemory_5d8c {
  strings:
    $key_5d8c = { 0a fe [2] 38 dc [2] 3e e9 [2] 10 e9 [2] 2f f5 }

  condition:
    any of them
}