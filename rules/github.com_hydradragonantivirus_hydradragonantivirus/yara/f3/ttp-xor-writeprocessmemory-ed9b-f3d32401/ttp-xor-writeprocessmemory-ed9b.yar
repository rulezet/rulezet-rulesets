rule TTP_XOR_WriteProcessMemory_ed9b {
  strings:
    $key_ed9b = { ba e9 [2] 88 cb [2] 8e fe [2] a0 fe [2] 9f e2 }

  condition:
    any of them
}