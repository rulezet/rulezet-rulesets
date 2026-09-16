rule TTP_XOR_WriteProcessMemory_33e2 {
  strings:
    $key_33e2 = { 64 90 [2] 56 b2 [2] 50 87 [2] 7e 87 [2] 41 9b }

  condition:
    any of them
}