rule TTP_XOR_WriteProcessMemory_59d9 {
  strings:
    $key_59d9 = { 0e ab [2] 3c 89 [2] 3a bc [2] 14 bc [2] 2b a0 }

  condition:
    any of them
}