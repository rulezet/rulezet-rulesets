rule TTP_XOR_WriteProcessMemory_559b {
  strings:
    $key_559b = { 02 e9 [2] 30 cb [2] 36 fe [2] 18 fe [2] 27 e2 }

  condition:
    any of them
}