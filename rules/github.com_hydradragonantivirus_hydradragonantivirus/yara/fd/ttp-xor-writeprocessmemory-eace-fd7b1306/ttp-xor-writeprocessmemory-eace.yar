rule TTP_XOR_WriteProcessMemory_eace {
  strings:
    $key_eace = { bd bc [2] 8f 9e [2] 89 ab [2] a7 ab [2] 98 b7 }

  condition:
    any of them
}