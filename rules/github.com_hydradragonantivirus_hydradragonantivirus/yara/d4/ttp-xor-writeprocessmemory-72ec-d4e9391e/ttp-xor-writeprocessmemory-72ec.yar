rule TTP_XOR_WriteProcessMemory_72ec {
  strings:
    $key_72ec = { 25 9e [2] 17 bc [2] 11 89 [2] 3f 89 [2] 00 95 }

  condition:
    any of them
}