rule TTP_XOR_WriteProcessMemory_c9ec {
  strings:
    $key_c9ec = { 9e 9e [2] ac bc [2] aa 89 [2] 84 89 [2] bb 95 }

  condition:
    any of them
}