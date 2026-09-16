rule TTP_XOR_WriteProcessMemory_d5ec {
  strings:
    $key_d5ec = { 82 9e [2] b0 bc [2] b6 89 [2] 98 89 [2] a7 95 }

  condition:
    any of them
}