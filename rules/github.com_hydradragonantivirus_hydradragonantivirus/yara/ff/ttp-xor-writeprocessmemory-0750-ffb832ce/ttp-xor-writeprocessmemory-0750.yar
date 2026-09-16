rule TTP_XOR_WriteProcessMemory_0750 {
  strings:
    $key_0750 = { 50 22 [2] 62 00 [2] 64 35 [2] 4a 35 [2] 75 29 }

  condition:
    any of them
}