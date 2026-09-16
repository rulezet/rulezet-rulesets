rule TTP_XOR_WriteProcessMemory_34d9 {
  strings:
    $key_34d9 = { 63 ab [2] 51 89 [2] 57 bc [2] 79 bc [2] 46 a0 }

  condition:
    any of them
}