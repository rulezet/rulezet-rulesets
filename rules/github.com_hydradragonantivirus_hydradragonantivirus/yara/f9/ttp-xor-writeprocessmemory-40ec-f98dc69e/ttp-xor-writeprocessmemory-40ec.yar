rule TTP_XOR_WriteProcessMemory_40ec {
  strings:
    $key_40ec = { 17 9e [2] 25 bc [2] 23 89 [2] 0d 89 [2] 32 95 }

  condition:
    any of them
}