rule TTP_XOR_WriteProcessMemory_27ec {
  strings:
    $key_27ec = { 70 9e [2] 42 bc [2] 44 89 [2] 6a 89 [2] 55 95 }

  condition:
    any of them
}