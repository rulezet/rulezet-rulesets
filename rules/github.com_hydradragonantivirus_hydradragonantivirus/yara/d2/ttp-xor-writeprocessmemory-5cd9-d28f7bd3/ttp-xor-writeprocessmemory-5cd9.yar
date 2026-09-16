rule TTP_XOR_WriteProcessMemory_5cd9 {
  strings:
    $key_5cd9 = { 0b ab [2] 39 89 [2] 3f bc [2] 11 bc [2] 2e a0 }

  condition:
    any of them
}