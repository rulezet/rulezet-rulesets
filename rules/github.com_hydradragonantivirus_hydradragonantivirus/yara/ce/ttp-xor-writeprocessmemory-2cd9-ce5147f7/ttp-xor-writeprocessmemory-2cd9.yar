rule TTP_XOR_WriteProcessMemory_2cd9 {
  strings:
    $key_2cd9 = { 7b ab [2] 49 89 [2] 4f bc [2] 61 bc [2] 5e a0 }

  condition:
    any of them
}