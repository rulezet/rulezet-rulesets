rule TTP_XOR_WriteProcessMemory_ff9b {
  strings:
    $key_ff9b = { a8 e9 [2] 9a cb [2] 9c fe [2] b2 fe [2] 8d e2 }

  condition:
    any of them
}