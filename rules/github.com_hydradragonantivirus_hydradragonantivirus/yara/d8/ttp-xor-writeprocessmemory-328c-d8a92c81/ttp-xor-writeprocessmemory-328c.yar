rule TTP_XOR_WriteProcessMemory_328c {
  strings:
    $key_328c = { 65 fe [2] 57 dc [2] 51 e9 [2] 7f e9 [2] 40 f5 }

  condition:
    any of them
}