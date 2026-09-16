rule TTP_XOR_WriteProcessMemory_138c {
  strings:
    $key_138c = { 44 fe [2] 76 dc [2] 70 e9 [2] 5e e9 [2] 61 f5 }

  condition:
    any of them
}