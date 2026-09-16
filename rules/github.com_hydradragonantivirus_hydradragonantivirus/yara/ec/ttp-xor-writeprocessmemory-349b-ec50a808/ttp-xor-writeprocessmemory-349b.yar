rule TTP_XOR_WriteProcessMemory_349b {
  strings:
    $key_349b = { 63 e9 [2] 51 cb [2] 57 fe [2] 79 fe [2] 46 e2 }

  condition:
    any of them
}