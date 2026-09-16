rule TTP_XOR_WriteProcessMemory_e2b9 {
  strings:
    $key_e2b9 = { b5 cb [2] 87 e9 [2] 81 dc [2] af dc [2] 90 c0 }

  condition:
    any of them
}