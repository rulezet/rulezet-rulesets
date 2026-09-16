rule TTP_XOR_WriteProcessMemory_45ec {
  strings:
    $key_45ec = { 12 9e [2] 20 bc [2] 26 89 [2] 08 89 [2] 37 95 }

  condition:
    any of them
}