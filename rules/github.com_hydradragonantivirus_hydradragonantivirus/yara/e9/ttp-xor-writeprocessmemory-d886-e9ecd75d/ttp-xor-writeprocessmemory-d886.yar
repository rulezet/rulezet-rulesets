rule TTP_XOR_WriteProcessMemory_d886 {
  strings:
    $key_d886 = { 8f f4 [2] bd d6 [2] bb e3 [2] 95 e3 [2] aa ff }

  condition:
    any of them
}