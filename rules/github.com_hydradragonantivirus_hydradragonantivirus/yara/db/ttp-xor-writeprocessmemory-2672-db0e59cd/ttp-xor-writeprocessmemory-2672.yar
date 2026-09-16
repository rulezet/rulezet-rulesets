rule TTP_XOR_WriteProcessMemory_2672 {
  strings:
    $key_2672 = { 71 00 [2] 43 22 [2] 45 17 [2] 6b 17 [2] 54 0b }

  condition:
    any of them
}