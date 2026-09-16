rule TTP_XOR_WriteProcessMemory_29ec {
  strings:
    $key_29ec = { 7e 9e [2] 4c bc [2] 4a 89 [2] 64 89 [2] 5b 95 }

  condition:
    any of them
}