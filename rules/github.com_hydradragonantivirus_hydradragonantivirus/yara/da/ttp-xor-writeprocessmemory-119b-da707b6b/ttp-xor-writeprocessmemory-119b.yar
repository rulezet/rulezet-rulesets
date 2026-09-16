rule TTP_XOR_WriteProcessMemory_119b {
  strings:
    $key_119b = { 46 e9 [2] 74 cb [2] 72 fe [2] 5c fe [2] 63 e2 }

  condition:
    any of them
}