rule TTP_XOR_WriteProcessMemory_7521 {
  strings:
    $key_7521 = { 22 53 [2] 10 71 [2] 16 44 [2] 38 44 [2] 07 58 }

  condition:
    any of them
}