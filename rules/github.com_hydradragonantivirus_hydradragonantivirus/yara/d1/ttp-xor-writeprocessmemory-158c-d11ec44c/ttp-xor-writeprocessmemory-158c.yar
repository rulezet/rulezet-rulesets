rule TTP_XOR_WriteProcessMemory_158c {
  strings:
    $key_158c = { 42 fe [2] 70 dc [2] 76 e9 [2] 58 e9 [2] 67 f5 }

  condition:
    any of them
}