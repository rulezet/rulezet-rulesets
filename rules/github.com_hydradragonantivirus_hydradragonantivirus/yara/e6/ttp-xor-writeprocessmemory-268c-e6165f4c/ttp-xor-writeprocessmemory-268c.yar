rule TTP_XOR_WriteProcessMemory_268c {
  strings:
    $key_268c = { 71 fe [2] 43 dc [2] 45 e9 [2] 6b e9 [2] 54 f5 }

  condition:
    any of them
}