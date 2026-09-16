rule TTP_XOR_WriteProcessMemory_508c {
  strings:
    $key_508c = { 07 fe [2] 35 dc [2] 33 e9 [2] 1d e9 [2] 22 f5 }

  condition:
    any of them
}