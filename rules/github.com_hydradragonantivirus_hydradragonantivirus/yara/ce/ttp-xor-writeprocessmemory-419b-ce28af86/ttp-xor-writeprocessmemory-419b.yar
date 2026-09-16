rule TTP_XOR_WriteProcessMemory_419b {
  strings:
    $key_419b = { 16 e9 [2] 24 cb [2] 22 fe [2] 0c fe [2] 33 e2 }

  condition:
    any of them
}