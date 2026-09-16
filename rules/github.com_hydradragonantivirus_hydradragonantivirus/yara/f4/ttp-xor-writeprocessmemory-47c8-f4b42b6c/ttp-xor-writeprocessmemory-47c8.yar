rule TTP_XOR_WriteProcessMemory_47c8 {
  strings:
    $key_47c8 = { 10 ba [2] 22 98 [2] 24 ad [2] 0a ad [2] 35 b1 }

  condition:
    any of them
}