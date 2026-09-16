rule TTP_XOR_WriteProcessMemory_219b {
  strings:
    $key_219b = { 76 e9 [2] 44 cb [2] 42 fe [2] 6c fe [2] 53 e2 }

  condition:
    any of them
}