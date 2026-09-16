rule TTP_XOR_WriteProcessMemory_749b {
  strings:
    $key_749b = { 23 e9 [2] 11 cb [2] 17 fe [2] 39 fe [2] 06 e2 }

  condition:
    any of them
}