rule TTP_XOR_WriteProcessMemory_7d34 {
  strings:
    $key_7d34 = { 2a 46 [2] 18 64 [2] 1e 51 [2] 30 51 [2] 0f 4d }

  condition:
    any of them
}