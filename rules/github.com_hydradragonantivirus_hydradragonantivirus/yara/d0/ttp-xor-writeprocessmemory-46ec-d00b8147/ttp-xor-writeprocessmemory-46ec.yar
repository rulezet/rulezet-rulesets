rule TTP_XOR_WriteProcessMemory_46ec {
  strings:
    $key_46ec = { 11 9e [2] 23 bc [2] 25 89 [2] 0b 89 [2] 34 95 }

  condition:
    any of them
}