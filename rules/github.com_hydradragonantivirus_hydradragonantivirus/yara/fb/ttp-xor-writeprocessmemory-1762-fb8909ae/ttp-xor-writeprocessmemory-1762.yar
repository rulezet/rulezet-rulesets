rule TTP_XOR_WriteProcessMemory_1762 {
  strings:
    $key_1762 = { 40 10 [2] 72 32 [2] 74 07 [2] 5a 07 [2] 65 1b }

  condition:
    any of them
}