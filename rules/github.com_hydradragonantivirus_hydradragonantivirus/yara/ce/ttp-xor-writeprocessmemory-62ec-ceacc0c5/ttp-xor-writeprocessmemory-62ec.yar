rule TTP_XOR_WriteProcessMemory_62ec {
  strings:
    $key_62ec = { 35 9e [2] 07 bc [2] 01 89 [2] 2f 89 [2] 10 95 }

  condition:
    any of them
}