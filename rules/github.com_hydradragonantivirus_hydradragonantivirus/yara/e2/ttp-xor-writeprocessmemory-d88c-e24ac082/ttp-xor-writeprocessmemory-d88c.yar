rule TTP_XOR_WriteProcessMemory_d88c {
  strings:
    $key_d88c = { 8f fe [2] bd dc [2] bb e9 [2] 95 e9 [2] aa f5 }

  condition:
    any of them
}