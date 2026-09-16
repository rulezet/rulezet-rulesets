rule TTP_XOR_WriteProcessMemory_d898 {
  strings:
    $key_d898 = { 8f ea [2] bd c8 [2] bb fd [2] 95 fd [2] aa e1 }

  condition:
    any of them
}