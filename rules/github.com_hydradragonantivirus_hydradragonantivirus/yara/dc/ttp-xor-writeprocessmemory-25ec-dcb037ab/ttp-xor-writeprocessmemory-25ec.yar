rule TTP_XOR_WriteProcessMemory_25ec {
  strings:
    $key_25ec = { 72 9e [2] 40 bc [2] 46 89 [2] 68 89 [2] 57 95 }

  condition:
    any of them
}