rule TTP_XOR_WriteProcessMemory_e2f0 {
  strings:
    $key_e2f0 = { b5 82 [2] 87 a0 [2] 81 95 [2] af 95 [2] 90 89 }

  condition:
    any of them
}