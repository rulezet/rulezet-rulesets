rule TTP_XOR_WriteProcessMemory_af9b {
  strings:
    $key_af9b = { f8 e9 [2] ca cb [2] cc fe [2] e2 fe [2] dd e2 }

  condition:
    any of them
}