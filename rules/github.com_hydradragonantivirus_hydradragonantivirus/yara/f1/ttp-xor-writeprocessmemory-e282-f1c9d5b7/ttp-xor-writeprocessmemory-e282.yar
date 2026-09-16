rule TTP_XOR_WriteProcessMemory_e282 {
  strings:
    $key_e282 = { b5 f0 [2] 87 d2 [2] 81 e7 [2] af e7 [2] 90 fb }

  condition:
    any of them
}