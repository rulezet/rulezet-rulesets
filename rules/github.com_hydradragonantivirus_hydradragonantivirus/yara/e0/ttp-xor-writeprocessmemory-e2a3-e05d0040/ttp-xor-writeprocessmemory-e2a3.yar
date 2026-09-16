rule TTP_XOR_WriteProcessMemory_e2a3 {
  strings:
    $key_e2a3 = { b5 d1 [2] 87 f3 [2] 81 c6 [2] af c6 [2] 90 da }

  condition:
    any of them
}