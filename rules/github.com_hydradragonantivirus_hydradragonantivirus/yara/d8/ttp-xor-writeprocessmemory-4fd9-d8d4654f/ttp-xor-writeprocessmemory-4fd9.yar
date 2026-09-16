rule TTP_XOR_WriteProcessMemory_4fd9 {
  strings:
    $key_4fd9 = { 18 ab [2] 2a 89 [2] 2c bc [2] 02 bc [2] 3d a0 }

  condition:
    any of them
}