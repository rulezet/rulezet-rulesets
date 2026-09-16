rule TTP_XOR_WriteProcessMemory_33d9 {
  strings:
    $key_33d9 = { 64 ab [2] 56 89 [2] 50 bc [2] 7e bc [2] 41 a0 }

  condition:
    any of them
}