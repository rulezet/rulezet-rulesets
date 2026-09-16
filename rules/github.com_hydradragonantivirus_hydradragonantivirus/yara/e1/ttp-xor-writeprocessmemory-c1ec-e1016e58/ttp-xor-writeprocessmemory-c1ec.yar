rule TTP_XOR_WriteProcessMemory_c1ec {
  strings:
    $key_c1ec = { 96 9e [2] a4 bc [2] a2 89 [2] 8c 89 [2] b3 95 }

  condition:
    any of them
}