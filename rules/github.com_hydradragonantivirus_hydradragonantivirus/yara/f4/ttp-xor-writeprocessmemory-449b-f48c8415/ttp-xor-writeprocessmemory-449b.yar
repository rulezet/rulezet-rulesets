rule TTP_XOR_WriteProcessMemory_449b {
  strings:
    $key_449b = { 13 e9 [2] 21 cb [2] 27 fe [2] 09 fe [2] 36 e2 }

  condition:
    any of them
}