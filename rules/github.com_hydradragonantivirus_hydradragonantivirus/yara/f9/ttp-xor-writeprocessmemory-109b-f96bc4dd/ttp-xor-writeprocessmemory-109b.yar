rule TTP_XOR_WriteProcessMemory_109b {
  strings:
    $key_109b = { 47 e9 [2] 75 cb [2] 73 fe [2] 5d fe [2] 62 e2 }

  condition:
    any of them
}