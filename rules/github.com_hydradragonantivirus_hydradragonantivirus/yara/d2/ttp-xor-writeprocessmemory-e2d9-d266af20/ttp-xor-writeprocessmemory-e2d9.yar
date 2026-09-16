rule TTP_XOR_WriteProcessMemory_e2d9 {
  strings:
    $key_e2d9 = { b5 ab [2] 87 89 [2] 81 bc [2] af bc [2] 90 a0 }

  condition:
    any of them
}