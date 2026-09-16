rule TTP_XOR_WriteProcessMemory_d6ec {
  strings:
    $key_d6ec = { 81 9e [2] b3 bc [2] b5 89 [2] 9b 89 [2] a4 95 }

  condition:
    any of them
}