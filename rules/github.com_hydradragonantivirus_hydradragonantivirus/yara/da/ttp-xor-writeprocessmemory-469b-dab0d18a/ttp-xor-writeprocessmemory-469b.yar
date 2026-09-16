rule TTP_XOR_WriteProcessMemory_469b {
  strings:
    $key_469b = { 11 e9 [2] 23 cb [2] 25 fe [2] 0b fe [2] 34 e2 }

  condition:
    any of them
}