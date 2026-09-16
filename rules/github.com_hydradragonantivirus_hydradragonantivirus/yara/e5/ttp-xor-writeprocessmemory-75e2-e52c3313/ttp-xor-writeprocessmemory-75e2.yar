rule TTP_XOR_WriteProcessMemory_75e2 {
  strings:
    $key_75e2 = { 22 90 [2] 10 b2 [2] 16 87 [2] 38 87 [2] 07 9b }

  condition:
    any of them
}