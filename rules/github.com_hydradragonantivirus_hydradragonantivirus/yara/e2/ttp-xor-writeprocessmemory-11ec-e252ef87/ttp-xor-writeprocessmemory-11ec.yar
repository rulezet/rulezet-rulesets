rule TTP_XOR_WriteProcessMemory_11ec {
  strings:
    $key_11ec = { 46 9e [2] 74 bc [2] 72 89 [2] 5c 89 [2] 63 95 }

  condition:
    any of them
}