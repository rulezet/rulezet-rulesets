rule TTP_XOR_WriteProcessMemory_1bce {
  strings:
    $key_1bce = { 4c bc [2] 7e 9e [2] 78 ab [2] 56 ab [2] 69 b7 }

  condition:
    any of them
}