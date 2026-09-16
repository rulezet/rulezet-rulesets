rule TTP_XOR_WriteProcessMemory_7ece {
  strings:
    $key_7ece = { 29 bc [2] 1b 9e [2] 1d ab [2] 33 ab [2] 0c b7 }

  condition:
    any of them
}