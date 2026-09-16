rule TTP_XOR_WriteProcessMemory_5731 {
  strings:
    $key_5731 = { 00 43 [2] 32 61 [2] 34 54 [2] 1a 54 [2] 25 48 }

  condition:
    any of them
}