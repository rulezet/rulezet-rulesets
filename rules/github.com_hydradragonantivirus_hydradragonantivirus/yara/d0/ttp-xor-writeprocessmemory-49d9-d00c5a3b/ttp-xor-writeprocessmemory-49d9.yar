rule TTP_XOR_WriteProcessMemory_49d9 {
  strings:
    $key_49d9 = { 1e ab [2] 2c 89 [2] 2a bc [2] 04 bc [2] 3b a0 }

  condition:
    any of them
}