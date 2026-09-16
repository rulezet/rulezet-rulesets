rule TTP_XOR_WriteProcessMemory_13b2 {
  strings:
    $key_13b2 = { 44 c0 [2] 76 e2 [2] 70 d7 [2] 5e d7 [2] 61 cb }

  condition:
    any of them
}