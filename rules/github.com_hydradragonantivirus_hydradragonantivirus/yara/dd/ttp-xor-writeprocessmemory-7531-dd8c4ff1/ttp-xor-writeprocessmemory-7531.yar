rule TTP_XOR_WriteProcessMemory_7531 {
  strings:
    $key_7531 = { 22 43 [2] 10 61 [2] 16 54 [2] 38 54 [2] 07 48 }

  condition:
    any of them
}