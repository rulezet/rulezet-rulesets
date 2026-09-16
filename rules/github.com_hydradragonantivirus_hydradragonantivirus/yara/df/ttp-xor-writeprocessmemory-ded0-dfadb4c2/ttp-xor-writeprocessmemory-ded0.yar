rule TTP_XOR_WriteProcessMemory_ded0 {
  strings:
    $key_ded0 = { 89 a2 [2] bb 80 [2] bd b5 [2] 93 b5 [2] ac a9 }

  condition:
    any of them
}