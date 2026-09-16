rule TTP_XOR_WriteProcessMemory_4d20 {
  strings:
    $key_4d20 = { 1a 52 [2] 28 70 [2] 2e 45 [2] 00 45 [2] 3f 59 }

  condition:
    any of them
}