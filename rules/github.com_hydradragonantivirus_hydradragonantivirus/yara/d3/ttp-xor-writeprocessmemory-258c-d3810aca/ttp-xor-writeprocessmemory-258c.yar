rule TTP_XOR_WriteProcessMemory_258c {
  strings:
    $key_258c = { 72 fe [2] 40 dc [2] 46 e9 [2] 68 e9 [2] 57 f5 }

  condition:
    any of them
}