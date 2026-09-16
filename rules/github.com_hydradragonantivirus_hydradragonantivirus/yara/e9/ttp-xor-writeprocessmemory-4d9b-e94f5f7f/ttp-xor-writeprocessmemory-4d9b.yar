rule TTP_XOR_WriteProcessMemory_4d9b {
  strings:
    $key_4d9b = { 1a e9 [2] 28 cb [2] 2e fe [2] 00 fe [2] 3f e2 }

  condition:
    any of them
}