rule TTP_XOR_WriteProcessMemory_579b {
  strings:
    $key_579b = { 00 e9 [2] 32 cb [2] 34 fe [2] 1a fe [2] 25 e2 }

  condition:
    any of them
}