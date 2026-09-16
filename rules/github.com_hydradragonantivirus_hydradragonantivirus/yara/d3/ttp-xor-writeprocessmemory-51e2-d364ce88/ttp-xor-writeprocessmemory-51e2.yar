rule TTP_XOR_WriteProcessMemory_51e2 {
  strings:
    $key_51e2 = { 06 90 [2] 34 b2 [2] 32 87 [2] 1c 87 [2] 23 9b }

  condition:
    any of them
}