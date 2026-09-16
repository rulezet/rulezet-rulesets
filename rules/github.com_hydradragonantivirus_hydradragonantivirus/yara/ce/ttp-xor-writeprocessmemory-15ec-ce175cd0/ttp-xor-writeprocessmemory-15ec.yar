rule TTP_XOR_WriteProcessMemory_15ec {
  strings:
    $key_15ec = { 42 9e [2] 70 bc [2] 76 89 [2] 58 89 [2] 67 95 }

  condition:
    any of them
}