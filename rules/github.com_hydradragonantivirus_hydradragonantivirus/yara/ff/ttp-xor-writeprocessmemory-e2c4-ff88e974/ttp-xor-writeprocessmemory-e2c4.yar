rule TTP_XOR_WriteProcessMemory_e2c4 {
  strings:
    $key_e2c4 = { b5 b6 [2] 87 94 [2] 81 a1 [2] af a1 [2] 90 bd }

  condition:
    any of them
}