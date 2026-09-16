rule TTP_XOR_WriteProcessMemory_eece {
  strings:
    $key_eece = { b9 bc [2] 8b 9e [2] 8d ab [2] a3 ab [2] 9c b7 }

  condition:
    any of them
}