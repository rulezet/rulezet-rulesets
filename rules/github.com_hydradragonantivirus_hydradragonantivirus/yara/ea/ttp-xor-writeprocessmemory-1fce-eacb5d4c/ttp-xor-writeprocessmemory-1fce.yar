rule TTP_XOR_WriteProcessMemory_1fce {
  strings:
    $key_1fce = { 48 bc [2] 7a 9e [2] 7c ab [2] 52 ab [2] 6d b7 }

  condition:
    any of them
}