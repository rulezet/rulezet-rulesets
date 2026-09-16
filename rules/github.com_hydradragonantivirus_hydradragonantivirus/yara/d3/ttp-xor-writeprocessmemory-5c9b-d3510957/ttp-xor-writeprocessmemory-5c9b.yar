rule TTP_XOR_WriteProcessMemory_5c9b {
  strings:
    $key_5c9b = { 0b e9 [2] 39 cb [2] 3f fe [2] 11 fe [2] 2e e2 }

  condition:
    any of them
}