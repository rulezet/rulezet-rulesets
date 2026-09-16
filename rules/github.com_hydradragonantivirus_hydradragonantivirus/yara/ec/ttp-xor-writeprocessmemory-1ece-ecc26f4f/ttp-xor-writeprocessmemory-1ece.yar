rule TTP_XOR_WriteProcessMemory_1ece {
  strings:
    $key_1ece = { 49 bc [2] 7b 9e [2] 7d ab [2] 53 ab [2] 6c b7 }

  condition:
    any of them
}