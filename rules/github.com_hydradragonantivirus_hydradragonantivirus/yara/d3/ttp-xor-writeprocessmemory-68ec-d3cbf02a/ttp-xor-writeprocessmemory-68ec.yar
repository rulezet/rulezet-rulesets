rule TTP_XOR_WriteProcessMemory_68ec {
  strings:
    $key_68ec = { 3f 9e [2] 0d bc [2] 0b 89 [2] 25 89 [2] 1a 95 }

  condition:
    any of them
}