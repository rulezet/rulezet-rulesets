rule TTP_XOR_WriteProcessMemory_7731 {
  strings:
    $key_7731 = { 20 43 [2] 12 61 [2] 14 54 [2] 3a 54 [2] 05 48 }

  condition:
    any of them
}