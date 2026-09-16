rule TTP_XOR_WriteProcessMemory_7c8c {
  strings:
    $key_7c8c = { 2b fe [2] 19 dc [2] 1f e9 [2] 31 e9 [2] 0e f5 }

  condition:
    any of them
}