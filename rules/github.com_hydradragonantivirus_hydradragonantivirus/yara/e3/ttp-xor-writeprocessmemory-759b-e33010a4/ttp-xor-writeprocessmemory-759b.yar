rule TTP_XOR_WriteProcessMemory_759b {
  strings:
    $key_759b = { 22 e9 [2] 10 cb [2] 16 fe [2] 38 fe [2] 07 e2 }

  condition:
    any of them
}