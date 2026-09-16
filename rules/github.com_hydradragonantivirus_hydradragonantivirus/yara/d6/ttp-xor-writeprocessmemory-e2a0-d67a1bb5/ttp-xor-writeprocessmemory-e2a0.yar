rule TTP_XOR_WriteProcessMemory_e2a0 {
  strings:
    $key_e2a0 = { b5 d2 [2] 87 f0 [2] 81 c5 [2] af c5 [2] 90 d9 }

  condition:
    any of them
}