rule TTP_XOR_WriteProcessMemory_c2ec {
  strings:
    $key_c2ec = { 95 9e [2] a7 bc [2] a1 89 [2] 8f 89 [2] b0 95 }

  condition:
    any of them
}