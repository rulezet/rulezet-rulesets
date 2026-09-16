rule TTP_XOR_WriteProcessMemory_e2ec {
  strings:
    $key_e2ec = { b5 9e [2] 87 bc [2] 81 89 [2] af 89 [2] 90 95 }

  condition:
    any of them
}