rule TTP_XOR_WriteProcessMemory_79ec {
  strings:
    $key_79ec = { 2e 9e [2] 1c bc [2] 1a 89 [2] 34 89 [2] 0b 95 }

  condition:
    any of them
}