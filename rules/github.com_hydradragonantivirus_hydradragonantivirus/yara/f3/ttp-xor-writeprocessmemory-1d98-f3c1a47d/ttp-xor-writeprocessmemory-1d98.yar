rule TTP_XOR_WriteProcessMemory_1d98 {
  strings:
    $key_1d98 = { 4a ea [2] 78 c8 [2] 7e fd [2] 50 fd [2] 6f e1 }

  condition:
    any of them
}