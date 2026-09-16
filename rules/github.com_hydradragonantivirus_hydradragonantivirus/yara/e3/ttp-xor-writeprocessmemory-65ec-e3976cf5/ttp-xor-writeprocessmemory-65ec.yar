rule TTP_XOR_WriteProcessMemory_65ec {
  strings:
    $key_65ec = { 32 9e [2] 00 bc [2] 06 89 [2] 28 89 [2] 17 95 }

  condition:
    any of them
}