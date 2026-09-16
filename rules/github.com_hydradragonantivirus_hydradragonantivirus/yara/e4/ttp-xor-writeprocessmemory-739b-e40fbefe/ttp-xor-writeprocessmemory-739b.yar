rule TTP_XOR_WriteProcessMemory_739b {
  strings:
    $key_739b = { 24 e9 [2] 16 cb [2] 10 fe [2] 3e fe [2] 01 e2 }

  condition:
    any of them
}