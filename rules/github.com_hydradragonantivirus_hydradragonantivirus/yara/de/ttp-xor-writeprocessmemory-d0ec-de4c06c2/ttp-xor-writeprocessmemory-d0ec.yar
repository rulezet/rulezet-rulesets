rule TTP_XOR_WriteProcessMemory_d0ec {
  strings:
    $key_d0ec = { 87 9e [2] b5 bc [2] b3 89 [2] 9d 89 [2] a2 95 }

  condition:
    any of them
}