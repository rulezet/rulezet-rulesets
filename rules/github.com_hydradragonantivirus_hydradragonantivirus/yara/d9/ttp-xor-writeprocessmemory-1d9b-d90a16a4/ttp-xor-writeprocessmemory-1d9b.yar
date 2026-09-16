rule TTP_XOR_WriteProcessMemory_1d9b {
  strings:
    $key_1d9b = { 4a e9 [2] 78 cb [2] 7e fe [2] 50 fe [2] 6f e2 }

  condition:
    any of them
}