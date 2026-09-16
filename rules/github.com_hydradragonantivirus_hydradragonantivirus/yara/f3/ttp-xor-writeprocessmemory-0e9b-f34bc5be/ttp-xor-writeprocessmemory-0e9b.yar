rule TTP_XOR_WriteProcessMemory_0e9b {
  strings:
    $key_0e9b = { 59 e9 [2] 6b cb [2] 6d fe [2] 43 fe [2] 7c e2 }

  condition:
    any of them
}