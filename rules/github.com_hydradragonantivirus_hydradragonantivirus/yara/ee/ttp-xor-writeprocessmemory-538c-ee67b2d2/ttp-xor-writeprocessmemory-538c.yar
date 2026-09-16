rule TTP_XOR_WriteProcessMemory_538c {
  strings:
    $key_538c = { 04 fe [2] 36 dc [2] 30 e9 [2] 1e e9 [2] 21 f5 }

  condition:
    any of them
}