rule TTP_XOR_WriteProcessMemory_7dec {
  strings:
    $key_7dec = { 2a 9e [2] 18 bc [2] 1e 89 [2] 30 89 [2] 0f 95 }

  condition:
    any of them
}