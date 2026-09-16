rule TTP_XOR_WriteProcessMemory_0eb9 {
  strings:
    $key_0eb9 = { 59 cb [2] 6b e9 [2] 6d dc [2] 43 dc [2] 7c c0 }

  condition:
    any of them
}