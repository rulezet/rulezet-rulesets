rule TTP_XOR_WriteProcessMemory_57c8 {
  strings:
    $key_57c8 = { 00 ba [2] 32 98 [2] 34 ad [2] 1a ad [2] 25 b1 }

  condition:
    any of them
}