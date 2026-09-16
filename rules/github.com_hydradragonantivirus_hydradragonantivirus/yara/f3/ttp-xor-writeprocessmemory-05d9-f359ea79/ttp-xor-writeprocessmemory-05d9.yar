rule TTP_XOR_WriteProcessMemory_05d9 {
  strings:
    $key_05d9 = { 52 ab [2] 60 89 [2] 66 bc [2] 48 bc [2] 77 a0 }

  condition:
    any of them
}