rule TTP_XOR_WriteProcessMemory_429b {
  strings:
    $key_429b = { 15 e9 [2] 27 cb [2] 21 fe [2] 0f fe [2] 30 e2 }

  condition:
    any of them
}