rule TTP_XOR_WriteProcessMemory_348c {
  strings:
    $key_348c = { 63 fe [2] 51 dc [2] 57 e9 [2] 79 e9 [2] 46 f5 }

  condition:
    any of them
}