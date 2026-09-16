rule TTP_XOR_WriteProcessMemory_54ec {
  strings:
    $key_54ec = { 03 9e [2] 31 bc [2] 37 89 [2] 19 89 [2] 26 95 }

  condition:
    any of them
}