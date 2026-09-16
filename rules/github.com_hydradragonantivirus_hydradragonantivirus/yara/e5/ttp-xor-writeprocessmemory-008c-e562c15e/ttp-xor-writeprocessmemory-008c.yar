rule TTP_XOR_WriteProcessMemory_008c {
  strings:
    $key_008c = { 57 fe [2] 65 dc [2] 63 e9 [2] 4d e9 [2] 72 f5 }

  condition:
    any of them
}