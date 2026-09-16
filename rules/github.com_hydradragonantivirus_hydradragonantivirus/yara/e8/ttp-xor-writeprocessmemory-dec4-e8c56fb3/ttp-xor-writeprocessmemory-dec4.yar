rule TTP_XOR_WriteProcessMemory_dec4 {
  strings:
    $key_dec4 = { 89 b6 [2] bb 94 [2] bd a1 [2] 93 a1 [2] ac bd }

  condition:
    any of them
}