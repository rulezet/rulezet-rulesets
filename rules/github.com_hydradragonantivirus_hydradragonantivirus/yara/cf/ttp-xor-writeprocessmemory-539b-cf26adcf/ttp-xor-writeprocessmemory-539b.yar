rule TTP_XOR_WriteProcessMemory_539b {
  strings:
    $key_539b = { 04 e9 [2] 36 cb [2] 30 fe [2] 1e fe [2] 21 e2 }

  condition:
    any of them
}